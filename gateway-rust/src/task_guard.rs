// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The decision guard on heartbeat tasks: an AI cannot make a task that destroys data.
//!
//! A heartbeat task is an automation: once written it runs on a schedule with nobody watching. The
//! operator's rule: a person may decide that an automation deletes things, an AI
//! acting through an MCP door or an agent run may not. So a write to a DESTRUCTIVE task by a
//! credential that is not a person is not applied. It becomes a PROPOSAL, in the queue user
//! management already uses (`noo_user_proposals`, action `heartbeat_task`), and a person approves it
//! there; approval creates or updates the task with `authorised_by` set to that person.
//!
//! ## Who is "a person"
//!
//! [`origin_of`]: a credential with NO `harness` claim and NO `act`. A `harness` claim marks the MCP
//! operator door, `mcp-external`, a node and a worker (`human_only_apply` tests the same claim); `act`
//! marks a delegated or exchanged token (an agent run, an add-on's exchange). A request with no
//! account at all (the cluster credential) is not a person either. A person must also hold the role
//! the task needs ([`Verdict::min_role`]): Operator for most, Admin for a scheduled
//! `entity_cleanup` apply, because the cleanup itself is admin-only.
//!
//! ## What is destructive
//!
//! One declaration, [`ACTION_CLASSES`], one row per heartbeat action. An action that is not in it is
//! DESTRUCTIVE (fail closed), and a test pins that every action the gateway registers has a row.
//!
//! * retention, purge, rotation and teardown actions are destructive always;
//! * `graph_prune` is destructive unless it is a dry run, `entity_cleanup` unless `apply` is false;
//! * a `pipeline` is as destructive as its worst step;
//! * everything else is not: reads, reports, research, digests, checks, backups, derived-data
//!   rebuilds, and the actions that deliver a message to a channel (nothing is lost by it, and what
//!   reaches a channel is already held to general messages by the egress floor). A `custom_prompt`
//!   run is an agent run whose own tool calls go through the approval layer.
//!
//! ## What the rule covers
//!
//! * create or edit (`POST /api/heartbeat/tasks`, `/schedule`): a non-person's write is a proposal
//!   when the new spec is destructive OR the task being edited already is. The live task is left
//!   as it was. A non-destructive task is written directly, as before.
//! * enable: a non-person switching a destructive task ON is a proposal. Switching it OFF is safe
//!   and direct. Deleting a task is safe and direct.
//! * run now: a non-person may not trigger a destructive task (it runs on its schedule).
//!
//! Approval re-classifies the stored spec at decision time, so a change to the table between
//! proposal and approval is honoured.

use serde_json::{json, Value};

use crate::auth::{RequesterCtx, Role};

// ───────────────────────────── classification ─────────────────────────────

/// How an action is classified.
#[derive(Debug, Clone, Copy)]
pub enum Class {
    /// Never destroys data. The text says why, for the table's reader.
    Safe(&'static str),
    /// Always destructive: the text is what goes to the operator ("deletes data").
    Always(&'static str),
    /// Destructive unless `config.dry_run` is exactly `true` (absent is a dry run).
    UnlessDryRun(&'static str),
    /// Destructive unless `config.apply` is exactly `false` or absent (the entity cleanup).
    OnlyWhenApply(&'static str),
    /// Destructive when any step of `config.steps` is.
    Pipeline,
}

/// Every heartbeat action, declared once. Order is only for the reader.
pub const ACTION_CLASSES: &[(&str, Class)] = &[
    // ── retention, purge, rotation, teardown: destructive always ──
    ("heartbeat_retention", Class::Always("deletes old run records")),
    ("agent_messages_retention", Class::Always("deletes old agent messages")),
    ("usage_rollup", Class::Always("drops raw usage partitions")),
    ("audit_log_rotate", Class::Always("drops old audit-log partitions")),
    ("memory_cleanup", Class::Always("deletes old conversations")),
    ("idle_scaledown", Class::Always("stops model backends")),
    ("cert_auto_rotate", Class::Always("replaces live certificates")),
    // ── destructive unless a preview ──
    ("graph_prune", Class::UnlessDryRun("deletes graph entities and edges")),
    ("entity_cleanup", Class::OnlyWhenApply("deletes junk graph entities")),
    // ── composite ──
    ("pipeline", Class::Pipeline),
    // ── reads, reports, checks ──
    ("cluster_health", Class::Safe("reads node health; may alert")),
    ("cost_report", Class::Safe("reads usage")),
    ("security_audit", Class::Safe("reads auth and rate-limit records")),
    ("cert_rotation_check", Class::Safe("reads certificate expiry")),
    ("disk_cleanup", Class::Safe("report-only: lists what could be cleaned")),
    ("self_benchmark", Class::Safe("runs test prompts")),
    ("memory_relevance_audit", Class::Safe("runs test queries")),
    ("channel_keepalive", Class::Safe("probes channels")),
    ("agent_self_check", Class::Safe("checks the agent loop; retries other safe actions")),
    // ── writes of its own, additive ──
    ("write_log", Class::Safe("writes its own log file")),
    ("database_backup", Class::Safe("adds a backup dump")),
    ("backup_knowledge", Class::Safe("adds snapshot files")),
    ("model_cache_warm", Class::Safe("pulls models onto nodes")),
    ("rag_reindex", Class::Safe("reads the embedding backlog")),
    // ── derived data that regenerates ──
    ("graph_clustering", Class::Safe("rebuilds derived clusters")),
    ("graph_signals", Class::Safe("recomputes derived scores")),
    ("knowledge_refresh", Class::Safe("re-ingests changed source documents")),
    ("thought_experiment", Class::Safe("rehearses retrieval; adds traversals")),
    ("continue_pending_tasks", Class::Safe("resumes background work")),
    // ── model-written text, some delivered to a channel (general messages only) ──
    ("research_report", Class::Safe("web research; writes a report")),
    ("structured_research", Class::Safe("web research; writes a report")),
    ("research_and_send", Class::Safe("research, delivered to a channel")),
    ("daily_briefing", Class::Safe("summarises status")),
    ("news_scan", Class::Safe("reads feeds; may ingest")),
    ("goal_review", Class::Safe("reviews goals")),
    ("chat_digest", Class::Safe("summarises a channel")),
    ("conversation_summarize", Class::Safe("adds summaries")),
    ("channel_message", Class::Safe("delivers a message to a channel")),
    ("custom_prompt", Class::Safe("an agent run; its tool calls pass the approval layer")),
];

/// The class of `action`, if it is declared.
pub fn class_of(action: &str) -> Option<&'static Class> {
    ACTION_CLASSES.iter().find(|(a, _)| *a == action).map(|(_, c)| c)
}

/// What a task's spec amounts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub destructive: bool,
    /// General wording for the operator and the caller: no data names.
    pub why: String,
    /// The lowest role a person must hold to decide this.
    pub min_role: Role,
}

impl Verdict {
    fn safe() -> Self {
        Verdict { destructive: false, why: String::new(), min_role: Role::Operator }
    }
    fn destructive(why: impl Into<String>, min_role: Role) -> Self {
        Verdict { destructive: true, why: why.into(), min_role }
    }
}

const MAX_PIPELINE_DEPTH: usize = 4;

/// Actions that write a file whose name or directory the config can set. The actions confine their
/// own output (`confine.rs`); a config that tries to leave the default workspace is also treated as
/// destructive, so it is a proposal rather than a quiet refusal at run time.
const WRITES_FILES: &[&str] = &["write_log", "research_report", "structured_research", "research_and_send"];

/// `config.output.destinations` with a `file` entry (or one that cannot be read): the result text is
/// written to a path the config names.
fn file_destination(config: &Value) -> Option<&'static str> {
    let d = config.get("output")?.get("destinations")?;
    match d {
        Value::Null => None,
        Value::Array(a) => a
            .iter()
            .any(|x| !x.is_object() || x.get("type").and_then(Value::as_str).is_none_or(|t| t == "file"))
            .then_some("writes its result to a file path the task names"),
        _ => Some("writes its result to a file path the task names"),
    }
}

fn output_path_override(config: &Value) -> Option<&'static str> {
    if let Some(v) = config.get("workspace_dir") {
        if !v.is_null() && v.as_str() != Some("") {
            return Some("writes outside the default workspace");
        }
    }
    match config.get("filename") {
        None | Some(Value::Null) => None,
        Some(Value::String(f)) => {
            let bad = f.starts_with('/')
                || f.starts_with('\\')
                || f.contains('\\')
                || f.contains('\0')
                || f.split('/').any(|c| c == "..")
                || f.get(1..2) == Some(":");
            bad.then_some("writes to a path outside the workspace")
        }
        Some(_) => Some("writes to a path outside the workspace"),
    }
}

/// Classify an action with its config. An action with no row is destructive.
pub fn classify(action: &str, config: &Value) -> Verdict {
    classify_at(action, config, 0)
}

fn classify_at(action: &str, config: &Value, depth: usize) -> Verdict {
    if WRITES_FILES.contains(&action) {
        if let Some(why) = output_path_override(config) {
            return Verdict::destructive(why, Role::Operator);
        }
    }
    // Any action: a result routed to a file (`config.output.destinations[{type: "file"}]`).
    if let Some(why) = file_destination(config) {
        return Verdict::destructive(why, Role::Operator);
    }
    let Some(class) = class_of(action) else {
        return Verdict::destructive("is an action this gateway has not classified, so it is treated as one that deletes data", Role::Admin);
    };
    match class {
        Class::Safe(_) => Verdict::safe(),
        Class::Always(why) => Verdict::destructive(*why, Role::Operator),
        Class::UnlessDryRun(why) => match config.get("dry_run") {
            // Safe only when the key is ABSENT or exactly `true`. `null`, "true" and 1 are
            // not: the Python handler reads `config.get("dry_run", True)`, so a present `null`
            // is falsy there and applies.
            None | Some(Value::Bool(true)) => Verdict::safe(),
            _ => Verdict::destructive(*why, Role::Operator),
        },
        Class::OnlyWhenApply(why) => match config.get("apply") {
            None | Some(Value::Null) | Some(Value::Bool(false)) => Verdict::safe(),
            // The scheduled cleanup runs as an Admin, so only an Admin may decide it.
            _ => Verdict::destructive(*why, Role::Admin),
        },
        Class::Pipeline => {
            let Some(steps) = config.get("steps").and_then(Value::as_array) else {
                return Verdict::destructive("is a pipeline whose steps cannot be read", Role::Admin);
            };
            if depth >= MAX_PIPELINE_DEPTH {
                return Verdict::destructive("is a pipeline nested too deep to check", Role::Admin);
            }
            let mut worst = Verdict::safe();
            for step in steps {
                let v = match (step.get("action").and_then(Value::as_str), step) {
                    (Some(a), s) if s.is_object() => classify_at(a, s.get("config").unwrap_or(&Value::Null), depth + 1),
                    _ => Verdict::destructive("is a pipeline with a step that cannot be read", Role::Admin),
                };
                if v.destructive && (!worst.destructive || v.min_role > worst.min_role) {
                    worst = v;
                }
            }
            worst
        }
    }
}

// ───────────────────────────── who is deciding ─────────────────────────────

/// Who made a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A credential with no `harness` claim and no `act`.
    Person { account: String, role: Role },
    /// Anything else. `via` says how, for the proposal's record.
    Agent { account: String, via: String },
}

/// The test, pure so it can be pinned.
pub fn origin_of_requester(r: Option<&RequesterCtx>) -> Origin {
    let Some(r) = r else {
        return Origin::Agent { account: "agent".into(), via: "a credential with no account".into() };
    };
    // A service identity is not a person even though its token carries no harness or act: an
    // add-on exchange (`addon:<name>`), a service key, a peer, the gateway's own tasks.
    const SERVICE_SUBJECTS: &[&str] = &["addon:", "svc:", "peer:", "heartbeat:", "internal:", "key:", "worker:", "node:", "kiosk:"];
    if let Some(p) = SERVICE_SUBJECTS.iter().find(|p| r.sub.starts_with(**p)) {
        return Origin::Agent { account: r.sub.clone(), via: format!("a service identity ({p}…)") };
    }
    let account = crate::auth::account_of(&r.sub).to_string();
    if let Some(h) = &r.harness {
        return Origin::Agent { account, via: format!("harness {h}") };
    }
    if let Some(a) = &r.act {
        return Origin::Agent { account, via: format!("a delegated credential ({})", a.sub) };
    }
    Origin::Person { account, role: r.role }
}

pub fn origin_of(ctx: &Option<axum::Extension<RequesterCtx>>) -> Origin {
    origin_of_requester(ctx.as_ref().map(|axum::Extension(r)| r))
}

/// [`origin_of`], and a person must be a human ACCOUNT: an enabled row in `noo_users`. A credential
/// that passes the claim test but names no such account (a service identity with a plain-looking
/// name, a deleted or disabled user) is not a person.
pub async fn resolve_origin(db: &sqlx::PgPool, ctx: &Option<axum::Extension<RequesterCtx>>) -> Origin {
    match origin_of(ctx) {
        Origin::Person { account, role } => {
            let human: bool = crate::repo::users::is_enabled(db, &account)
                .await
                // Cannot tell: not a person.
                .unwrap_or(false);
            if human {
                Origin::Person { account, role }
            } else {
                Origin::Agent { account, via: "an account that is not an enabled user".into() }
            }
        }
        agent => agent,
    }
}

impl Origin {
    /// May this origin decide a task of `min_role`'s weight?
    pub fn may_decide(&self, min_role: Role) -> bool {
        matches!(self, Origin::Person { role, .. } if *role >= min_role)
    }
    pub fn account(&self) -> &str {
        match self {
            Origin::Person { account, .. } | Origin::Agent { account, .. } => account,
        }
    }
    /// What `created_by` records: taken from the credential, never from the request body.
    pub fn created_by(&self) -> String {
        match self {
            Origin::Person { account, .. } => account.clone(),
            Origin::Agent { .. } => "agent".into(),
        }
    }
    fn via(&self) -> String {
        match self {
            Origin::Person { .. } => "a person".into(),
            Origin::Agent { via, .. } => via.clone(),
        }
    }
}

// ───────────────────────────── the write ─────────────────────────────

/// A task as a create or edit request spells it.
#[derive(Debug, Clone)]
pub struct TaskSpec {
    pub id: String,
    pub name: String,
    pub schedule: String,
    pub action: String,
    pub config: Value,
    pub channels: Value,
    pub recipients: Value,
    pub enabled: bool,
    pub created_by: String,
}

impl TaskSpec {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id, "name": self.name, "schedule": self.schedule, "action": self.action,
            "config": self.config, "channels": self.channels, "recipients": self.recipients,
            "enabled": self.enabled, "created_by": self.created_by,
        })
    }
    fn from_json(v: &Value) -> Result<Self, String> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string).filter(|s| !s.trim().is_empty());
        let need = |k: &str| s(k).ok_or_else(|| format!("the proposed task has no {k}"));
        Ok(TaskSpec {
            id: need("id")?,
            name: need("name")?,
            schedule: need("schedule")?,
            action: need("action")?,
            config: v.get("config").cloned().filter(Value::is_object).unwrap_or_else(|| json!({})),
            channels: v.get("channels").cloned().unwrap_or_else(|| json!([])),
            recipients: v.get("recipients").cloned().unwrap_or_else(|| json!([])),
            enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            created_by: s("created_by").unwrap_or_else(|| "proposal".into()),
        })
    }
}

/// What a guarded write did.
#[derive(Debug, Clone, PartialEq)]
pub enum Written {
    /// The task row was written. `authorised_by` is the person recorded for a destructive task.
    Direct { authorised_by: Option<String> },
    /// Nothing was written: it is a proposal awaiting a person.
    Proposed { proposal_id: i32, why: String },
}

/// The words the caller is told. General: no task config, no data names.
pub fn proposal_message(why: &str, proposal_id: i32) -> String {
    format!(
        "Created as a proposal for the operator to approve: this task {why}. Nothing was created or changed; \
         it does not run until a person approves it (proposal {proposal_id}: noo heartbeat approve {proposal_id})."
    )
}

/// A hash of a task row's meaningful fields, taken when a proposal is filed and again when it is
/// decided: if the live task changed in between, the proposal was written against something that
/// is gone.
fn row_hash(action: &str, schedule: &str, config: &Value, enabled: bool, channels: &Value, recipients: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canon = json!({
        "action": action, "schedule": schedule, "config": config, "enabled": enabled,
        "channels": channels, "recipients": recipients,
    })
    .to_string();
    hex::encode(Sha256::digest(canon.as_bytes()))
}

type LiveRow = (String, String, Value, bool, Value, Value);

async fn live_row(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, id: &str) -> Result<Option<LiveRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT action, schedule, COALESCE(config, '{}'::jsonb), enabled, COALESCE(channels, '[]'::jsonb), \
                COALESCE(recipients, '[]'::jsonb) \
         FROM noo_heartbeat_tasks WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
}

fn live_hash(r: &Option<LiveRow>) -> Option<String> {
    r.as_ref().map(|(a, sc, c, e, ch, rc)| row_hash(a, sc, c, *e, ch, rc))
}

/// The recipients and Drive folders a spec names that no person has registered: not a saved
/// recipient a person created, not on another task a person authorised, not the configured reports
/// folder. Every action's result is delivered to its `channels`/`recipients`, so this covers every
/// action. A non-person may point a task at a registered target; a NEW target is a decision.
async fn new_targets(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, spec: &TaskSpec) -> Result<Vec<String>, sqlx::Error> {
    let mut wanted: Vec<String> = Vec::new();
    for r in spec.recipients.as_array().into_iter().flatten().filter_map(Value::as_str) {
        wanted.push(r.to_string());
    }
    for k in ["recipient", "drive_folder_id"] {
        match spec.config.get(k) {
            None | Some(Value::Null) => {}
            Some(Value::String(t)) if t.is_empty() => {}
            Some(Value::String(t)) => wanted.push(t.clone()),
            // a non-string target is not one we know
            Some(other) => wanted.push(other.to_string()),
        }
    }
    // The same source delivery reads (noo_settings first, then env), not env alone.
    let configured = crate::settings::get("NOO_REPORTS_DRIVE_FOLDER_ID").unwrap_or_default();
    let mut unknown = Vec::new();
    for t in wanted {
        if !configured.is_empty() && t == configured {
            continue;
        }
        let known: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM noo_channel_recipients WHERE recipient_id = $1 AND created_by IS NOT NULL) \
                 OR EXISTS (SELECT 1 FROM noo_heartbeat_tasks WHERE id <> $2 AND authorised_by IS NOT NULL AND ( \
                        recipients @> to_jsonb($1::text) OR config->>'recipient' = $1 OR config->>'drive_folder_id' = $1))",
        )
        .bind(&t)
        .bind(&spec.id)
        .fetch_one(&mut **tx)
        .await?;
        if !known {
            unknown.push(t);
        }
    }
    Ok(unknown)
}

/// Write a task through the guard: directly, or as a proposal.
///
/// `source` is how the request arrived (`create`, `schedule`, `enable`), recorded on a proposal.
pub async fn write_task(
    db: &sqlx::PgPool,
    origin: &Origin,
    spec: &TaskSpec,
    source: &str,
) -> Result<Written, sqlx::Error> {
    let mut spec = spec.clone();
    // `created_by` comes from the credential, never from the request body.
    spec.created_by = origin.created_by();
    let spec = &spec;
    let mut tx = db.begin().await?;
    // The row being edited, locked so the decision and the write see the same task.
    let existing = live_row(&mut tx, &spec.id).await?;
    let new = classify(&spec.action, &spec.config);
    let old = existing.as_ref().map(|(a, _, c, ..)| classify(a, c));
    let touches_destructive = new.destructive || old.as_ref().is_some_and(|o| o.destructive);
    let mut min_role = Role::Operator;
    let mut why = String::new();
    let mut needs_person = false;
    if touches_destructive {
        needs_person = true;
        min_role = match &old {
            Some(o) if o.destructive && o.min_role > new.min_role => o.min_role,
            _ => new.min_role,
        };
        why = if new.destructive { new.why.clone() } else { old.map(|o| o.why).unwrap_or_default() };
    } else if !matches!(origin, Origin::Person { .. }) {
        // A non-person sending to a recipient or folder nobody registered is a new decision.
        let fresh = new_targets(&mut tx, spec).await?;
        if !fresh.is_empty() {
            needs_person = true;
            why = "sends to a channel recipient or Drive folder that is not registered".into();
        }
    }
    if needs_person && !origin.may_decide(min_role) {
        let base = live_hash(&existing);
        let (pid, fresh) = insert_proposal(&mut tx, origin, spec, source, &why, existing.is_some(), base).await?;
        tx.commit().await?;
        tracing::warn!(task_id = %spec.id, proposal_id = pid, via = %origin.via(), "heartbeat_task_proposed");
        if fresh {
            notify_operator(pid, &why).await;
        }
        return Ok(Written::Proposed { proposal_id: pid, why });
    }
    upsert(&mut tx, spec).await?;
    let person = match origin {
        Origin::Person { account, .. } => Some(account.as_str()),
        Origin::Agent { .. } => None,
    };
    let authorised_by = record_authorisation(&mut tx, spec, &new, person).await?;
    tx.commit().await?;
    Ok(Written::Direct { authorised_by })
}

async fn upsert(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, spec: &TaskSpec) -> Result<(), sqlx::Error> {
    crate::repo::heartbeat::upsert_task(
        &mut **tx,
        &crate::repo::heartbeat::TaskDef {
            id: &spec.id,
            name: &spec.name,
            schedule: &spec.schedule,
            action: &spec.action,
            config: &spec.config,
            channels: &spec.channels,
            recipients: &spec.recipients,
            enabled: spec.enabled,
            created_by: &spec.created_by,
        },
    )
    .await
    .map(|_| ())
}

/// Settings that decide WHERE results go. Setting one needs a person (`POST /api/settings/flags/set`
/// refuses anything else), because a door that could set the reports folder would redirect every
/// report, and the target rule above treats the configured folder as already registered.
pub const EGRESS_TARGET_SETTINGS: &[&str] = &["NOO_REPORTS_DRIVE_FOLDER_ID"];

/// Agent-turn actions that are not on the LLM list: `self_benchmark` runs `config.test_prompts`
/// through the coordinator with every tool; `continue_pending_tasks` resumes coordinator sessions
/// (it runs in Python, outside the Rust ceiling, and pipelines refuse it).
pub const AGENT_TURN_EXTRA: &[&str] = &["self_benchmark", "continue_pending_tasks"];

/// Whether the action's runs are agent turns: model-written text driving unattended tool calls
/// (`custom_prompt`, but equally `channel_message`'s prompt, a goal review, research instructions,
/// a digest or briefing). Every one of them gets the read-only ceiling until a person authorises it.
pub fn is_agent_turn_action(action: &str) -> bool {
    crate::heartbeat_actions::is_llm_driven_action(action) || AGENT_TURN_EXTRA.contains(&action)
}

/// Whether a spec names where its result is delivered.
fn has_targets(spec: &TaskSpec) -> bool {
    let nonempty = |v: &Value| v.as_array().is_some_and(|a| !a.is_empty());
    nonempty(&spec.channels) || nonempty(&spec.recipients) || ["recipient", "drive_folder_id"].iter().any(|k| spec.config.get(*k).is_some_and(|v| !v.is_null() && v.as_str() != Some("")))
}

/// Record who authorised a task: a destructive one, an agent-turn one (whose runs may call
/// mutating tools only when a person authorised it) or one that delivers somewhere (its targets
/// count as registered only if a person set them). `person` is `Some` only for a person's own
/// write or approval; any other write CLEARS the record, which is the revocation. For the scheduled
/// cleanup the record carries the exact settings the person saw.
async fn record_authorisation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    spec: &TaskSpec,
    verdict: &Verdict,
    person: Option<&str>,
) -> Result<Option<String>, sqlx::Error> {
    let needs_record = verdict.destructive || is_agent_turn_action(&spec.action) || has_targets(spec);
    let Some(account) = person.filter(|_| needs_record) else {
        sqlx::query("UPDATE noo_heartbeat_tasks SET authorised_by = NULL, authorised_at = NULL, authorised_config = NULL WHERE id = $1")
            .bind(&spec.id)
            .execute(&mut **tx)
            .await?;
        return Ok(None);
    };
    let fp = crate::entity_cleanup_task::fingerprint_of(&spec.action, &spec.config);
    sqlx::query("UPDATE noo_heartbeat_tasks SET authorised_by = $2, authorised_at = now(), authorised_config = $3 WHERE id = $1")
        .bind(&spec.id)
        .bind(account)
        .bind(fp)
        .execute(&mut **tx)
        .await?;
    tracing::warn!(task_id = %spec.id, account, why = %verdict.why, "heartbeat_task_authorised");
    Ok(Some(account.to_string()))
}

/// Insert a proposal, or return the identical pending one: the same task spec against the same live
/// row is one proposal however many times it is asked for. `true` when a row was added.
async fn insert_proposal(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    origin: &Origin,
    spec: &TaskSpec,
    source: &str,
    why: &str,
    replaces: bool,
    base_hash: Option<String>,
) -> Result<(i32, bool), sqlx::Error> {
    let task = spec.to_json();
    let dup: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM noo_user_proposals WHERE action = $1 AND status = 'pending' \
           AND payload->'task' = $2 AND payload->>'base_hash' IS NOT DISTINCT FROM $3 ORDER BY id LIMIT 1",
    )
    .bind(PROPOSAL_ACTION)
    .bind(&task)
    .bind(&base_hash)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((id,)) = dup {
        return Ok((id, false));
    }
    let payload = json!({
        "task": task,
        "source": source,
        "why": why,
        "replaces": replaces,
        "base_hash": base_hash,
        "proposed_by": {"account": origin.account(), "via": origin.via()},
    });
    let (pid,): (i32,) = sqlx::query_as(
        "INSERT INTO noo_user_proposals (action, payload, note, requested_by) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(PROPOSAL_ACTION)
    .bind(payload)
    .bind(format!("scheduled task that {why}"))
    .bind(origin.account())
    .fetch_one(&mut **tx)
    .await?;
    Ok((pid, true))
}

/// The `noo_user_proposals.action` of a task proposal.
pub const PROPOSAL_ACTION: &str = "heartbeat_task";

async fn notify_operator(pid: i32, why: &str) {
    // A general line: the kind of change and a reference. The spec is in the proposal, not here.
    let text = format!(
        "Task proposal #{pid}: a request for a scheduled task that {why} needs approval. \
         Review: noo heartbeat proposals {pid}. Decide: noo heartbeat approve {pid} or noo heartbeat reject {pid}."
    );
    crate::routes::users::notify_approval_channels(&text).await;
}

/// Enable or disable a task through the guard. Disabling is always direct; enabling a destructive
/// task is a proposal unless a person does it. `Ok(None)` is "no such task".
pub async fn set_enabled(
    db: &sqlx::PgPool,
    origin: &Origin,
    task_id: &str,
    enabled: bool,
) -> Result<Option<Written>, sqlx::Error> {
    if !enabled {
        let rows = crate::repo::heartbeat::set_enabled(db, task_id, false).await?;
        return Ok((rows > 0).then_some(Written::Direct { authorised_by: None }));
    }
    let row: Option<(String, String, String, String, Value, Value, Value, String, bool)> = sqlx::query_as(
        "SELECT id, name, schedule, action, COALESCE(config, '{}'::jsonb), COALESCE(channels, '[]'::jsonb), \
                COALESCE(recipients, '[]'::jsonb), COALESCE(created_by, 'system'), enabled \
         FROM noo_heartbeat_tasks WHERE id = $1",
    )
    .bind(task_id)
    .fetch_optional(db)
    .await?;
    let Some((id, name, schedule, action, config, channels, recipients, created_by, live_enabled)) = row else {
        return Ok(None);
    };
    let v = classify(&action, &config);
    if v.destructive && !origin.may_decide(v.min_role) {
        let base = Some(row_hash(&action, &schedule, &config, live_enabled, &channels, &recipients));
        let spec = TaskSpec { id, name, schedule, action, config, channels, recipients, enabled: true, created_by };
        let mut tx = db.begin().await?;
        let (pid, fresh) = insert_proposal(&mut tx, origin, &spec, "enable", &v.why, true, base).await?;
        tx.commit().await?;
        if fresh {
            notify_operator(pid, &v.why).await;
        }
        return Ok(Some(Written::Proposed { proposal_id: pid, why: v.why }));
    }
    let rows = crate::repo::heartbeat::set_enabled(db, task_id, true).await?;
    Ok((rows > 0).then_some(Written::Direct { authorised_by: None }))
}

/// What a guarded schedule change did.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduleChange {
    pub written: Written,
    /// The schedule the task had when the request was decided.
    pub old_schedule: String,
    /// The task's `next_run` after a direct write (`None` = recomputed on the next tick).
    pub next_run: Option<chrono::DateTime<chrono::Utc>>,
}

/// Change only a task's schedule, through the guard. A destructive task's schedule is part of what a
/// person authorised, so anyone who could not decide the task itself files a proposal (the live row
/// with the new schedule, the same edit-proposal an edit through `write_task` files); everything else
/// is a direct write of the `schedule` column alone. `Ok(None)` is "no such task".
pub async fn set_schedule(
    db: &sqlx::PgPool,
    origin: &Origin,
    task_id: &str,
    schedule: &str,
) -> Result<Option<ScheduleChange>, sqlx::Error> {
    let mut tx = db.begin().await?;
    let row: Option<(String, String, String, String, Value, Value, Value, String, bool)> = sqlx::query_as(
        "SELECT id, name, schedule, action, COALESCE(config, '{}'::jsonb), COALESCE(channels, '[]'::jsonb), \
                COALESCE(recipients, '[]'::jsonb), COALESCE(created_by, 'system'), enabled \
         FROM noo_heartbeat_tasks WHERE id = $1 FOR UPDATE",
    )
    .bind(task_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, name, old_schedule, action, config, channels, recipients, created_by, enabled)) = row else {
        return Ok(None);
    };
    let v = classify(&action, &config);
    if v.destructive && !origin.may_decide(v.min_role) {
        let base = Some(row_hash(&action, &old_schedule, &config, enabled, &channels, &recipients));
        let spec = TaskSpec { id, name, schedule: schedule.to_string(), action, config, channels, recipients, enabled, created_by };
        let (pid, fresh) = insert_proposal(&mut tx, origin, &spec, "schedule", &v.why, true, base).await?;
        tx.commit().await?;
        if fresh {
            notify_operator(pid, &v.why).await;
        }
        return Ok(Some(ScheduleChange { written: Written::Proposed { proposal_id: pid, why: v.why }, old_schedule, next_run: None }));
    }
    let next_run = crate::repo::heartbeat::set_schedule(&mut *tx, task_id, schedule).await?.flatten();
    tx.commit().await?;
    Ok(Some(ScheduleChange { written: Written::Direct { authorised_by: None }, old_schedule, next_run }))
}

/// May this origin trigger a run of `action` now? A destructive task runs on its schedule, or
/// when a person asks.
pub fn may_run_now(origin: &Origin, action: &str, config: &Value) -> Result<(), String> {
    let v = classify(action, config);
    if v.destructive && !origin.may_decide(v.min_role) {
        return Err(format!(
            "this task {}: only a person with the role it needs can run it now (it runs on its schedule); run `noo heartbeat run <task-id>` yourself",
            v.why
        ));
    }
    Ok(())
}

// ───────────────────────────── approval ─────────────────────────────

/// May `origin` approve this proposal? It re-classifies the stored spec now.
pub fn check_approver(origin: &Origin, payload: &Value) -> Result<(), String> {
    let spec = TaskSpec::from_json(payload.get("task").unwrap_or(&Value::Null))?;
    let v = classify(&spec.action, &spec.config);
    let min = if v.destructive { v.min_role } else { Role::Operator };
    match origin {
        Origin::Person { role, .. } if *role >= min => Ok(()),
        Origin::Person { .. } => Err(format!(
            "approving a task that {} needs {} access",
            v.why,
            if min == Role::Admin { "Admin" } else { "Operator" }
        )),
        Origin::Agent { via, .. } => Err(format!(
            "approving a scheduled task is a person's decision; this request came from {via}. Run `noo heartbeat approve <proposal-id>` yourself"
        )),
    }
}

/// Execute an approved proposal inside the decide transaction: create or update the task, with
/// `authorised_by` the approver. The caller has already run [`check_approver`].
///
/// The live row is locked first and three things are checked against it: the approver holds the role
/// the OLD and the NEW spec need (the higher), the stored spec is classified again, and the live
/// task is still the one the proposal was written against (`base_hash`); if it changed, nothing is
/// written and the proposer must file again.
pub async fn apply_approved(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    payload: &Value,
    approver: &Origin,
) -> Result<Value, String> {
    let Origin::Person { account, role } = approver else {
        return Err("approving a scheduled task is a person's decision".into());
    };
    let spec = TaskSpec::from_json(payload.get("task").unwrap_or(&Value::Null))?;
    crate::entity_cleanup_task::validate_write(&spec.action, &spec.config)?;
    let verdict = classify(&spec.action, &spec.config);
    let live = live_row(tx, &spec.id).await.map_err(|e| e.to_string())?;
    let base = payload.get("base_hash").and_then(Value::as_str).map(str::to_string);
    if live_hash(&live) != base {
        return Err("the task changed after this proposal was filed; reject it and have it proposed again".into());
    }
    let old = live.as_ref().map(|(a, _, c, ..)| classify(a, c));
    let mut min = if verdict.destructive { verdict.min_role } else { Role::Operator };
    if let Some(o) = &old {
        if o.destructive && o.min_role > min {
            min = o.min_role;
        }
    }
    if *role < min {
        return Err(format!("approving this needs {} access", if min == Role::Admin { "Admin" } else { "Operator" }));
    }
    upsert(tx, &spec).await.map_err(|e| e.to_string())?;
    let authorised_by = record_authorisation(tx, &spec, &verdict, Some(account)).await.map_err(|e| e.to_string())?;
    Ok(json!({
        "task_id": spec.id,
        "task": if live.is_some() { "updated" } else { "created" },
        "authorised_by": authorised_by,
        "enabled": spec.enabled,
    }))
}

// ───────────────────── agent-run tool ceiling ─────────────────────

/// The tools a limited run may call: an EXPLICIT allowlist of read-only tools that neither write nor
/// carry data out. Not "everything LOW": a LOW tool such as a web search can carry memory to a third
/// party in its query, and a tool added later must be listed here before it is available. A test
/// pins that each is still LOW risk.
pub const CEILING_ALLOWED: &[&str] = &[
    "noo_tool_search", "noo_rag_query", "noo_rag_status", "noo_cluster_status", "noo_memory_search",
    "noo_conversation_context", "noo_graph_search_entities", "noo_graph_entity_detail", "noo_graph_neighbors",
    "noo_graph_stats", "noo_graph_explain_path", "noo_graph_semantic_search", "noo_graph_classify_intent",
    "noo_graph_search_clusters", "noo_recall_search", "noo_recall_traversals", "noo_recall_status",
    "noo_recall_videos", "noo_recall_lifecycle_stats", "noo_recall_lifecycle_preview", "noo_recall_prominent",
    "noo_docs_list", "noo_doc_detail", "noo_models_cached", "noo_job_status", "noo_job_list", "noo_job_history",
    "noo_scheduler_status", "noo_workflow_list", "noo_channel_list", "noo_channel_list_recipients",
    "noo_prompt_skills_list", "noo_prompt_skills_get", "noo_approval_stats", "noo_heartbeat_list_actions",
    "noo_heartbeat_list_tasks", "noo_heartbeat_task_history", "noo_heartbeat_status", "noo_heartbeat_get_artifacts",
    "noo_config_get", "noo_memory_health", "noo_autonomy_status", "noo_autonomy_audit", "noo_op_status", "noo_op_list",
];

type Restricted = Vec<(String, Vec<String>)>;
static RESTRICTED_TURNS: std::sync::Mutex<Restricted> = std::sync::Mutex::new(Vec::new());

/// While held, tool calls in the heartbeat turn(s) of `conversation_id` are limited to read-only
/// tools. `take_denied` is what the run refused, for its result.
pub struct TurnCeiling(String);

impl TurnCeiling {
    pub fn take_denied(&self) -> Vec<String> {
        RESTRICTED_TURNS
            .lock()
            .ok()
            .and_then(|mut v| v.iter_mut().find(|(c, _)| *c == self.0).map(|(_, d)| std::mem::take(d)))
            .unwrap_or_default()
    }
}

impl Drop for TurnCeiling {
    fn drop(&mut self) {
        if let Ok(mut v) = RESTRICTED_TURNS.lock() {
            if let Some(i) = v.iter().position(|(c, _)| *c == self.0) {
                v.remove(i);
            }
        }
    }
}

/// The line a limited run adds to its result when the ceiling refused something: a quiet success
/// would hide that the task could not do what it was written to do.
pub fn denied_note(denied: &[String]) -> String {
    let mut names: Vec<&str> = denied.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    format!(
        "\n\n⚠️ Read-only limit: {} tool call(s) were refused ({}) because no person authorised this task. \
         A person edits the task (noo heartbeat add / import) or approves its proposal (noo heartbeat proposals).",
        denied.len(),
        names.join(", ")
    )
}

/// Limit a heartbeat run's tools unless a person authorised the task. EVERY agent-turn action is
/// covered (`is_agent_turn_action`): a task an agent made or edited keeps working, but its runs
/// may call read-only tools only; mutating tools (delete, cancel, drain, config, archive ...) and
/// data-carrying ones stay out of reach until a person has authorised it.
pub async fn ceiling_for_run(db: &sqlx::PgPool, task_id: &str, action: &str, conversation_id: &str) -> Option<TurnCeiling> {
    if !is_agent_turn_action(action) {
        return None;
    }
    let authorised: bool = sqlx::query_scalar("SELECT COALESCE(authorised_by IS NOT NULL, false) FROM noo_heartbeat_tasks WHERE id = $1")
        .bind(task_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
    if authorised {
        return None;
    }
    tracing::info!(task_id, "heartbeat_turn_tools_limited_to_read_only");
    RESTRICTED_TURNS.lock().ok()?.push((conversation_id.to_string(), Vec::new()));
    Some(TurnCeiling(conversation_id.to_string()))
}

/// Why `tool` may not run in the current turn, if the turn is a limited heartbeat run. A refusal is
/// remembered for the run's result.
pub fn turn_tool_denied(conversation_id: &str, channel: &str, tool: &str, _args: &Value) -> Option<String> {
    let allowed = CEILING_ALLOWED.contains(&tool);
    if conversation_id.is_empty() {
        // A heartbeat-owned turn with no conversation id cannot be matched to its task, so it is
        // treated as limited: fail closed. Other channels have no ceiling.
        if channel == "heartbeat" && !allowed {
            return Some(format!("{tool} is not available: this scheduled turn carries no task, so it is limited to read-only tools."));
        }
        return None;
    }
    let mut v = RESTRICTED_TURNS.lock().ok()?;
    let entry = v
        .iter_mut()
        .find(|(c, _)| conversation_id == c || conversation_id.starts_with(&format!("{c}-")))?;
    if allowed {
        return None;
    }
    entry.1.push(tool.to_string());
    Some(format!(
        "{tool} is not available to this scheduled task: it was not authorised by a person, so its runs are \
         limited to read-only tools. A person edits the task, or approves its proposal (noo heartbeat proposals)."
    ))
}

// ───────────────────── existing tasks and recipients (review-existing) ─────────────────────

/// Does this task need a recorded person? Destructive, an agent turn, or it names where results go.
fn needs_record(action: &str, config: &Value, channels: &Value, recipients: &Value) -> bool {
    let spec = TaskSpec {
        id: String::new(), name: String::new(), schedule: String::new(), action: action.into(), config: config.clone(),
        channels: channels.clone(), recipients: recipients.clone(), enabled: true, created_by: String::new(),
    };
    classify(action, config).destructive || is_agent_turn_action(action) || has_targets(&spec)
}

/// What a person still has to look at after an upgrade: tasks that predate the guard (or that no
/// person has authorised) and saved recipients with no recorded author. Until reviewed, the tasks run
/// read-only and their targets are not registered.
pub async fn pending_review(db: &sqlx::PgPool) -> Result<(Vec<Value>, Vec<Value>), sqlx::Error> {
    let rows: Vec<(String, String, String, String, Value, Value, Value, bool)> = sqlx::query_as(
        "SELECT id, name, schedule, action, COALESCE(config, '{}'::jsonb), COALESCE(channels, '[]'::jsonb), \
                COALESCE(recipients, '[]'::jsonb), enabled \
         FROM noo_heartbeat_tasks WHERE authorised_by IS NULL ORDER BY id",
    )
    .fetch_all(db)
    .await?;
    let tasks = rows
        .into_iter()
        .filter(|(_, _, _, a, c, ch, rc, _)| needs_record(a, c, ch, rc))
        .map(|(id, name, schedule, action, config, channels, recipients, enabled)| {
            let v = classify(&action, &config);
            json!({"id": id, "name": name, "schedule": schedule, "action": action, "config": config,
                   "channels": channels, "recipients": recipients, "enabled": enabled,
                   "destructive": v.destructive, "destructive_why": if v.destructive { json!(v.why) } else { Value::Null },
                   "min_role": v.min_role.as_str()})
        })
        .collect();
    let recipients: Vec<(String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, channel, recipient_id, display_name, notes FROM noo_channel_recipients WHERE created_by IS NULL ORDER BY channel, display_name",
    )
    .fetch_all(db)
    .await?;
    let recipients = recipients
        .into_iter()
        .map(|(id, channel, recipient_id, display_name, notes)| {
            json!({"id": id, "channel": channel, "recipient_id": recipient_id, "display_name": display_name, "notes": notes})
        })
        .collect();
    Ok((tasks, recipients))
}

/// How many items wait for `noo heartbeat review-existing`.
pub async fn review_count(db: &sqlx::PgPool) -> i64 {
    pending_review(db).await.map(|(t, r)| (t.len() + r.len()) as i64).unwrap_or(0)
}

/// A person approves existing tasks and saved recipients: each is recorded as authorised / created by
/// them, exactly as if they had saved it. A task that needs a higher role than theirs is skipped, and
/// anything no longer waiting is skipped. Returns `(tasks approved, recipients approved, skipped)`.
pub async fn approve_review(
    db: &sqlx::PgPool,
    person: &Origin,
    task_ids: &[String],
    recipient_ids: &[String],
) -> Result<(usize, usize, Vec<String>), sqlx::Error> {
    let Origin::Person { account, role } = person else { return Ok((0, 0, vec!["not a person".into()])) };
    let mut skipped = Vec::new();
    let mut tx = db.begin().await?;
    let mut approved = 0usize;
    for id in task_ids {
        let row: Option<(String, Value, Value, Value)> = sqlx::query_as(
            "SELECT action, COALESCE(config, '{}'::jsonb), COALESCE(channels, '[]'::jsonb), COALESCE(recipients, '[]'::jsonb) \
             FROM noo_heartbeat_tasks WHERE id = $1 AND authorised_by IS NULL FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((action, config, channels, recipients)) = row else {
            skipped.push(format!("{id}: not waiting"));
            continue;
        };
        if !needs_record(&action, &config, &channels, &recipients) {
            skipped.push(format!("{id}: nothing to review"));
            continue;
        }
        let v = classify(&action, &config);
        if v.destructive && *role < v.min_role {
            skipped.push(format!("{id}: needs {} access", v.min_role.as_str()));
            continue;
        }
        sqlx::query("UPDATE noo_heartbeat_tasks SET authorised_by = $2, authorised_at = now(), authorised_config = $3 WHERE id = $1")
            .bind(id)
            .bind(account)
            .bind(crate::entity_cleanup_task::fingerprint_of(&action, &config))
            .execute(&mut *tx)
            .await?;
        approved += 1;
    }
    let res = sqlx::query("UPDATE noo_channel_recipients SET created_by = $1 WHERE id = ANY($2) AND created_by IS NULL")
        .bind(account)
        .bind(recipient_ids)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::warn!(account = %account, tasks = approved, recipients = res.rows_affected(), "heartbeat_existing_reviewed");
    Ok((approved, res.rows_affected() as usize, skipped))
}

// ───────────────────────────── the listing ─────────────────────────────

/// What `GET /api/heartbeat/tasks` adds per task.
pub fn listing_view(action: &str, config: &Value, authorised_by: Option<&str>, authorised_at: Option<String>) -> Value {
    let v = classify(action, config);
    let mut out = json!({
        "destructive": v.destructive,
        "destructive_why": if v.destructive { json!(v.why) } else { Value::Null },
        "authorised_by": authorised_by,
        "authorised_at": authorised_at,
    });
    out["runs_read_only"] = json!(is_agent_turn_action(action) && authorised_by.is_none());
    if action == crate::entity_cleanup_task::ACTION {
        out["apply"] = json!(if v.destructive { "apply" } else { "preview" });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rc(sub: &str, role: Role, harness: Option<&str>, act: bool) -> RequesterCtx {
        RequesterCtx {
            sub: sub.into(),
            scopes: vec!["read".into(), "write".into(), "admin".into()],
            role,
            harness: harness.map(String::from),
            act: act.then(|| crate::auth::Actor { sub: "key:x".into(), iss_user: None, task: None }),
        }
    }

    #[test]
    fn only_a_credential_with_no_harness_and_no_act_is_a_person() {
        assert_eq!(
            origin_of_requester(Some(&rc("root/laptop", Role::Admin, None, false))),
            Origin::Person { account: "root".into(), role: Role::Admin }
        );
        for h in ["operator:x", "mcp-external:codex", "node:host3", "worker:run-1"] {
            assert!(matches!(origin_of_requester(Some(&rc("root", Role::Admin, Some(h), false))), Origin::Agent { .. }), "{h}");
        }
        assert!(matches!(origin_of_requester(Some(&rc("root", Role::Admin, None, true))), Origin::Agent { .. }), "act");
        assert!(matches!(origin_of_requester(None), Origin::Agent { .. }), "no account");
        let op = origin_of_requester(Some(&rc("olive", Role::Operator, None, false)));
        assert!(op.may_decide(Role::Operator) && !op.may_decide(Role::Admin), "a person below the task's role cannot decide it");
    }

    #[test]
    fn classification_follows_the_declaration() {
        let c = |a: &str, cfg: Value| classify(a, &cfg).destructive;
        // research, reports, previews: not destructive
        assert!(!c("research_report", json!({"topic": "x"})));
        assert!(!c("daily_briefing", json!({})));
        assert!(!c("channel_message", json!({"message": "hi"})));
        assert!(!c("graph_prune", json!({})), "graph_prune defaults to a dry run");
        assert!(!c("graph_prune", json!({"dry_run": true})));
        assert!(!c("entity_cleanup", json!({})));
        assert!(!c("entity_cleanup", json!({"apply": false, "max_delete": 5000})));
        // retention, purge, teardown: always
        for a in ["heartbeat_retention", "agent_messages_retention", "usage_rollup", "audit_log_rotate", "memory_cleanup", "idle_scaledown", "cert_auto_rotate"] {
            assert!(c(a, json!({"dry_run": true})), "{a} is destructive even as a preview");
        }
        // destructive when applying
        assert!(c("graph_prune", json!({"dry_run": false})));
        assert!(c("graph_prune", json!({"dry_run": "false"})), "anything but a true dry_run is an apply");
        assert!(c("entity_cleanup", json!({"apply": true})));
        assert!(c("entity_cleanup", json!({"apply": "yes"})), "a non-boolean apply fails closed");
        assert_eq!(classify("entity_cleanup", &json!({"apply": true})).min_role, Role::Admin);
        assert_eq!(classify("memory_cleanup", &json!({})).min_role, Role::Operator);
    }

    #[test]
    fn a_null_or_stringy_dry_run_is_an_apply_and_a_pipeline_cannot_hide_one() {
        for v in [json!(null), json!("true"), json!(1), json!(false), json!([])] {
            assert!(classify("graph_prune", &json!({"dry_run": v})).destructive, "dry_run {v}");
            let p = json!({"steps": [{"action": "research_report"}, {"action": "graph_prune", "config": {"dry_run": v}}]});
            assert!(classify("pipeline", &p).destructive, "pipeline step dry_run {v}");
        }
        assert!(!classify("graph_prune", &json!({"dry_run": true})).destructive);
        assert!(!classify("graph_prune", &json!({})).destructive);
        assert!(classify("graph_prune", &json!({"dry_run": null})).destructive, "present null is not an absent key");
    }

    #[test]
    fn a_log_or_report_aimed_outside_the_workspace_is_destructive() {
        for action in ["write_log", "research_report", "structured_research", "research_and_send"] {
            assert!(!classify(action, &json!({"filename": "heartbeat-{date}.md"})).destructive, "{action} plain");
            for bad in [
                json!({"filename": "/app/noomesh.yaml"}),
                json!({"filename": "../x.md"}),
                json!({"filename": "a/../../x.md"}),
                json!({"filename": "C:\\x.md"}),
                json!({"filename": 7}),
                json!({"workspace_dir": "/app"}),
                json!({"workspace_dir": "sub"}),
            ] {
                assert!(classify(action, &bad).destructive, "{action} {bad}");
            }
        }
        let p = json!({"steps": [{"action": "write_log", "config": {"filename": "/app/noomesh.yaml"}}]});
        assert!(classify("pipeline", &p).destructive);
        // a result routed to a file, on ANY action, at the top level or in a step
        let to_file = json!({"output": {"destinations": [{"type": "file", "path": "/app/noomesh.yaml"}]}});
        for action in ["cluster_health", "research_report", "daily_briefing", "write_log", "pipeline"] {
            assert!(classify(action, &to_file).destructive, "{action}");
        }
        let step = json!({"steps": [{"action": "cluster_health", "config": to_file}]});
        assert!(classify("pipeline", &step).destructive, "a pipeline step");
        for fine in [json!({}), json!({"output": {"destinations": [{"type": "rag_ingest"}, {"type": "channel"}]}}), json!({"output": {"destinations": []}})] {
            assert!(!classify("cluster_health", &fine).destructive, "{fine}");
        }
        assert!(classify("cluster_health", &json!({"output": {"destinations": [{"path": "x"}]}})).destructive, "an untyped destination fails closed");
        assert!(!classify("write_log", &json!({"workspace_dir": ""})).destructive, "an empty override is none");
    }

    #[test]
    fn the_ceiling_is_an_explicit_allowlist_of_low_risk_tools() {
        for t in CEILING_ALLOWED {
            assert!(crate::security::classify_tool_risk(t, &json!({})) <= crate::security::RiskLevel::Low, "{t} is no longer LOW risk");
        }
        for banned in ["web_search", "noo_web_search", "noo_agent_ack", "noo_task_done", "noo_graph_navigate", "noo_channel_read_messages"] {
            assert!(!CEILING_ALLOWED.contains(&banned), "{banned}");
        }
        // empty conversation id: a heartbeat-owned turn fails closed, another channel is not ours to limit
        assert!(turn_tool_denied("", "heartbeat", "noo_job_cancel", &json!({})).is_some());
        assert!(turn_tool_denied("", "heartbeat", "noo_rag_query", &json!({})).is_none());
        assert!(turn_tool_denied("", "dashboard", "noo_job_cancel", &json!({})).is_none());
        assert!(AGENT_TURN_EXTRA.iter().all(|a| is_agent_turn_action(a)));
        // every coordinator call reachable from heartbeat code is under a ceiling
        let allowed_fns = [
            ("heartbeat_actions.rs", "run_llm_action_inner"),   // under run_llm_action's ceiling
            ("heartbeat_actions.rs", "research_corrective_retry"), // only called from run_llm_action_inner
            ("heartbeat_actions.rs", "action_self_benchmark"),  // ceiling_for_run in run_rust_native_task
            ("research_pipeline.rs", "run_research_pipeline"),  // called from run_llm_action_inner
            ("research_pipeline.rs", "run_section"),            // called from run_research_pipeline
        ];
        for (file, src) in [("heartbeat_actions.rs", include_str!("heartbeat_actions.rs")), ("research_pipeline.rs", include_str!("research_pipeline.rs"))] {
            let mut cur = "";
            for line in src.lines() {
                let t = line.trim_start();
                if let Some(rest) = t.strip_prefix("pub async fn ").or_else(|| t.strip_prefix("async fn ")).or_else(|| t.strip_prefix("pub(crate) async fn ")).or_else(|| t.strip_prefix("fn ")) {
                    cur = rest.split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("");
                }
                if t.starts_with("//") || t.contains("\"coordinator") {
                    continue;
                }
                if t.contains("coordinator::run") && !t.starts_with("///") && !t.starts_with("//!") {
                    assert!(allowed_fns.contains(&(file, cur)), "{file}: `{cur}` calls the coordinator but is not under a task ceiling; run it through run_llm_action or give it a ceiling and list it here");
                }
            }
        }
        let ha = include_str!("heartbeat_actions.rs");
        let rt = &ha[ha.find("pub async fn run_rust_native_task(").unwrap()..];
        assert!(rt[..rt.find("\n}\n").unwrap()].contains("ceiling_for_run("), "self_benchmark runs under a ceiling");
    }

    #[test]
    fn a_service_identity_is_not_a_person() {
        for sub in ["addon:evolve", "svc:grafana", "peer:abc", "heartbeat:t", "internal:x", "key:codex", "worker:run", "node:host3", "kiosk:seat"] {
            assert!(matches!(origin_of_requester(Some(&rc(sub, Role::Admin, None, false))), Origin::Agent { .. }), "{sub}");
        }
    }

    #[test]
    fn an_unclassified_action_is_destructive() {
        let v = classify("made_up_action", &json!({}));
        assert!(v.destructive, "fail closed");
        assert_eq!(v.min_role, Role::Admin);
        assert!(class_of("made_up_action").is_none());
    }

    #[test]
    fn a_pipeline_is_as_destructive_as_its_worst_step() {
        let ok = json!({"steps": [{"action": "research_report", "config": {}}, {"action": "write_log"}]});
        assert!(!classify("pipeline", &ok).destructive);
        let bad = json!({"steps": [{"action": "research_report"}, {"action": "memory_cleanup", "config": {}}]});
        assert!(classify("pipeline", &bad).destructive);
        let nested = json!({"steps": [{"action": "pipeline", "config": bad}]});
        assert!(classify("pipeline", &nested).destructive, "nesting does not hide a step");
        let apply = json!({"steps": [{"action": "entity_cleanup", "config": {"apply": true}}]});
        assert_eq!(classify("pipeline", &apply).min_role, Role::Admin);
        for unreadable in [json!({}), json!({"steps": "x"}), json!({"steps": [1]}), json!({"steps": [{"name": "no action"}]}), json!({"steps": [{"action": "nope"}]})] {
            assert!(classify("pipeline", &unreadable).destructive, "{unreadable}");
        }
    }

    #[test]
    fn every_registered_action_is_classified() {
        use std::collections::BTreeSet;
        let mut registered: BTreeSet<String> = BTreeSet::new();
        let src = include_str!("heartbeat_actions.rs");
        for list in ["RUST_LLM_ACTIONS", "RUST_NATIVE_ACTIONS", "TRELLION_ACTIONS"] {
            let from = src.find(&format!("const {list}: &[&str] = &[")).unwrap_or_else(|| panic!("{list}"));
            let body = &src[from..];
            let body = &body[body.find('[').unwrap()..body.find("];").unwrap()];
            for line in body.lines() {
                let line = line.split("//").next().unwrap_or("");
                for part in line.split('"').skip(1).step_by(2) {
                    registered.insert(part.to_string());
                }
            }
        }
        // the actions the console is offered
        let routes = include_str!("routes/intelligence.rs");
        for chunk in routes.split("json!({\"name\": \"").skip(1) {
            let name = chunk.split('"').next().unwrap();
            if chunk[name.len()..].starts_with("\", \"description\"") {
                registered.insert(name.to_string());
            }
        }
        assert!(registered.len() >= 30, "the scan found only {registered:?}");
        let missing: Vec<&String> = registered.iter().filter(|a| class_of(a).is_none()).collect();
        assert!(missing.is_empty(), "heartbeat actions with no row in ACTION_CLASSES (they would be treated as destructive): {missing:?}");
        // and the table names nothing that no longer exists
        let stale: Vec<&str> = ACTION_CLASSES.iter().map(|(a, _)| *a).filter(|a| !registered.contains(*a) && !["audit_log_rotate", "continue_pending_tasks", "memory_relevance_audit", "pipeline", "structured_research"].contains(a)).collect();
        assert!(stale.is_empty(), "ACTION_CLASSES rows for actions nothing registers: {stale:?}");
    }

    #[test]
    fn the_callers_message_is_general() {
        let m = proposal_message("deletes old conversations", 12);
        assert!(m.starts_with("Created as a proposal for the operator to approve: this task deletes old conversations"), "{m}");
        assert!(m.contains("noo heartbeat approve 12"));
    }

    #[test]
    fn a_task_proposal_checks_its_approver_now() {
        let payload = |action: &str, config: Value| json!({"task": {"id": "t", "name": "t", "schedule": "0 1 * * *", "action": action, "config": config}});
        let person = Origin::Person { account: "root".into(), role: Role::Admin };
        let operator = Origin::Person { account: "olive".into(), role: Role::Operator };
        let agent = Origin::Agent { account: "root".into(), via: "harness operator:x".into() };
        assert!(check_approver(&person, &payload("memory_cleanup", json!({}))).is_ok());
        assert!(check_approver(&operator, &payload("memory_cleanup", json!({}))).is_ok());
        assert!(check_approver(&operator, &payload("entity_cleanup", json!({"apply": true}))).is_err(), "the cleanup needs an Admin");
        assert!(check_approver(&agent, &payload("memory_cleanup", json!({}))).is_err(), "an agent cannot approve");
        assert!(check_approver(&person, &payload("made_up", json!({}))).is_ok());
        assert!(check_approver(&operator, &payload("made_up", json!({}))).is_err(), "unclassified needs an Admin");
        assert!(check_approver(&person, &json!({"task": {"id": "t"}})).is_err(), "a spec that cannot be read");
    }

    // ───────────── against a real migrated schema (skips without NOO_BROKER_TEST_DSN) ─────────────

    use crate::ops::tests::{account, scratch, DB_LOCK};

    fn spec(id: &str, action: &str, config: Value) -> TaskSpec {
        TaskSpec {
            id: id.into(),
            name: id.into(),
            schedule: "30 7 * * 0".into(),
            action: action.into(),
            config,
            channels: json!([]),
            recipients: json!([]),
            enabled: true,
            created_by: "test".into(),
        }
    }

    async fn task_row(db: &sqlx::PgPool, id: &str) -> Option<(String, Value, bool, Option<String>)> {
        sqlx::query_as("SELECT action, config, enabled, authorised_by FROM noo_heartbeat_tasks WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .unwrap()
    }

    async fn proposals(db: &sqlx::PgPool) -> Vec<(i32, Value, String, String)> {
        sqlx::query_as("SELECT id, payload, status, requested_by FROM noo_user_proposals WHERE action = 'heartbeat_task' ORDER BY id")
            .fetch_all(db)
            .await
            .unwrap()
    }

    fn door() -> Origin {
        Origin::Agent { account: "root".into(), via: "harness operator:x".into() }
    }
    fn admin() -> Origin {
        Origin::Person { account: "root".into(), role: Role::Admin }
    }

    /// The security routes' proposal readers decode the real INT4 `id` column. They answered 500
    /// for every row on v0.2.92/v0.2.93-rc.1 (an `i64` decode), so no task proposal could be shown
    /// or approved — and nothing exercised these SELECTs against the real schema.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_security_routes_can_read_a_filed_proposal() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_proposal_read").await else { return };
        let _ = account(&db, "root", Role::Admin).await;
        let w = write_task(&db, &door(), &spec("nightly_prune", "graph_prune", json!({"dry_run": false})), "create").await.unwrap();
        let Written::Proposed { proposal_id, .. } = w else { panic!("expected a proposal, got {w:?}") };
        let rows = crate::routes::users::proposal_rows(&db).await.expect("the list decodes");
        assert!(rows.iter().any(|r| r.0 == proposal_id && r.1 == "heartbeat_task"), "{rows:?}");
        let one = crate::routes::users::proposal_row(&db, i64::from(proposal_id)).await.expect("by id decodes");
        assert_eq!(one.map(|r| (r.0, r.4)), Some((proposal_id, "pending".to_string())));
        assert!(crate::routes::users::proposal_row(&db, 999_999).await.expect("absent decodes").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ai_created_research_task_is_created_directly() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_research").await else { return };
        let w = write_task(&db, &door(), &spec("weekly_ai", "research_report", json!({"topic": "x"})), "create").await.unwrap();
        assert_eq!(w, Written::Direct { authorised_by: None });
        let row = task_row(&db, "weekly_ai").await.expect("the task exists");
        assert_eq!((row.0.as_str(), row.3), ("research_report", None));
        assert!(proposals(&db).await.is_empty(), "no proposal for a non-destructive task");
        // a dry-run cleanup and a preview prune are direct too
        for (id, a, c) in [("p1", "entity_cleanup", json!({"apply": false})), ("p2", "graph_prune", json!({})), ("p3", "entity_cleanup", json!({}))] {
            assert!(matches!(write_task(&db, &door(), &spec(id, a, c), "create").await.unwrap(), Written::Direct { .. }), "{id}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ai_created_destructive_task_becomes_a_proposal_and_a_person_approves_it() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_proposal").await else { return };
        let _ = account(&db, "root", Role::Admin).await;
        for (id, action, config) in [
            ("clean", "entity_cleanup", json!({"apply": true, "max_delete": 100})),
            ("convs", "memory_cleanup", json!({"max_age_days": 30})),
            ("ret", "heartbeat_retention", json!({"dry_run": true})),
            ("mystery", "made_up_action", json!({})),
        ] {
            let w = write_task(&db, &door(), &spec(id, action, config), "create").await.unwrap();
            let Written::Proposed { proposal_id, why } = w else { panic!("{id}: {w:?}") };
            assert!(proposal_id > 0 && !why.is_empty());
            assert!(task_row(&db, id).await.is_none(), "{id}: no task row exists until a person approves");
        }
        let rows = proposals(&db).await;
        assert_eq!(rows.len(), 4);
        let (pid, payload, status, by) = rows[0].clone();
        assert_eq!((status.as_str(), by.as_str()), ("pending", "root"));
        assert_eq!(payload["task"]["id"], "clean");
        assert_eq!(payload["task"]["config"]["max_delete"], 100, "the full spec is held");
        assert_eq!(payload["proposed_by"]["account"], "root");
        assert!(payload["proposed_by"]["via"].as_str().unwrap().contains("operator:x"), "who, and through what");

        // a person's credential approves: the task now exists, authorised by them
        let (_, payload_json, ..) = rows[0].clone();
        check_approver(&admin(), &payload_json).expect("an Admin may approve");
        let mut tx = db.begin().await.unwrap();
        let result = apply_approved(&mut tx, &payload_json, &admin()).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(result["authorised_by"], "root");
        let row = task_row(&db, "clean").await.expect("created on approval");
        assert_eq!((row.0.as_str(), row.1["apply"].clone(), row.3.as_deref()), ("entity_cleanup", json!(true), Some("root")));
        let _ = pid;
        // an agent cannot approve
        assert!(check_approver(&door(), &payload_json).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ai_edit_of_a_destructive_task_is_a_proposal_and_the_live_task_is_unchanged() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_edit").await else { return };
        // a person creates a destructive task directly
        let w = write_task(&db, &admin(), &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 100})), "create").await.unwrap();
        assert_eq!(w, Written::Direct { authorised_by: Some("root".into()) });
        let before = task_row(&db, "clean").await.unwrap();
        // an agent widens the cap
        let w = write_task(&db, &door(), &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 5000})), "create").await.unwrap();
        assert!(matches!(w, Written::Proposed { .. }), "{w:?}");
        assert_eq!(task_row(&db, "clean").await.unwrap(), before, "the live task is untouched");
        // an agent edit that changes nothing in the config is still a proposal (any field of a destructive task)
        let mut renamed = spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 100}));
        renamed.schedule = "* * * * *".into();
        assert!(matches!(write_task(&db, &door(), &renamed, "create").await.unwrap(), Written::Proposed { .. }));
        assert_eq!(task_row(&db, "clean").await.unwrap(), before);
        let sched: String = sqlx::query_scalar("SELECT schedule FROM noo_heartbeat_tasks WHERE id = 'clean'").fetch_one(&db).await.unwrap();
        assert_eq!(sched, "30 7 * * 0", "the schedule did not move");
        // an agent edit that makes a safe task destructive
        write_task(&db, &door(), &spec("r", "graph_prune", json!({})), "create").await.unwrap();
        assert!(matches!(write_task(&db, &door(), &spec("r", "graph_prune", json!({"dry_run": false})), "create").await.unwrap(), Written::Proposed { .. }));
        assert_eq!(task_row(&db, "r").await.unwrap().1, json!({}), "still the preview");
        // an Operator person cannot decide a task that needs an Admin
        let op = Origin::Person { account: "olive".into(), role: Role::Operator };
        assert!(matches!(write_task(&db, &op, &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 7})), "create").await.unwrap(), Written::Proposed { .. }));
        assert_eq!(proposals(&db).await.len(), 4);
        // a person's edit is direct and re-records them
        let w = write_task(&db, &admin(), &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 7})), "create").await.unwrap();
        assert_eq!(w, Written::Direct { authorised_by: Some("root".into()) });
        assert_eq!(task_row(&db, "clean").await.unwrap().1["max_delete"], 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ai_can_disable_and_delete_but_enabling_a_destructive_task_is_a_proposal() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_toggle").await else { return };
        write_task(&db, &admin(), &spec("convs", "memory_cleanup", json!({})), "create").await.unwrap();
        // disable: allowed directly
        let w = set_enabled(&db, &door(), "convs", false).await.unwrap();
        assert!(matches!(w, Some(Written::Direct { .. })));
        assert!(!task_row(&db, "convs").await.unwrap().2, "disabled");
        // enable by an agent: a proposal, the task stays off
        let w = set_enabled(&db, &door(), "convs", true).await.unwrap();
        assert!(matches!(w, Some(Written::Proposed { .. })), "{w:?}");
        assert!(!task_row(&db, "convs").await.unwrap().2, "still disabled");
        // enable by a person: direct
        assert!(matches!(set_enabled(&db, &admin(), "convs", true).await.unwrap(), Some(Written::Direct { .. })));
        assert!(task_row(&db, "convs").await.unwrap().2);
        // a safe task: an agent enables directly
        write_task(&db, &door(), &spec("rep", "research_report", json!({})), "create").await.unwrap();
        set_enabled(&db, &door(), "rep", false).await.unwrap();
        assert!(matches!(set_enabled(&db, &door(), "rep", true).await.unwrap(), Some(Written::Direct { .. })));
        assert!(set_enabled(&db, &door(), "nope", true).await.unwrap().is_none());
        // delete is the repo's, direct, and not guarded
        assert_eq!(crate::repo::heartbeat::delete_task(&db, "convs").await.unwrap(), 1);
        // an agent cannot run a destructive task now; it can run a safe one
        assert!(may_run_now(&door(), "memory_cleanup", &json!({})).is_err());
        assert!(may_run_now(&door(), "entity_cleanup", &json!({"apply": true})).is_err());
        assert!(may_run_now(&door(), "entity_cleanup", &json!({})).is_ok(), "a preview is fine");
        assert!(may_run_now(&door(), "research_report", &json!({})).is_ok());
        assert!(may_run_now(&admin(), "memory_cleanup", &json!({})).is_ok());
    }

    async fn full_row(db: &sqlx::PgPool, id: &str) -> (String, String, String, Value, Value, Value, bool, Option<chrono::DateTime<chrono::Utc>>) {
        sqlx::query_as(
            "SELECT name, schedule, action, config, channels, recipients, enabled, next_run FROM noo_heartbeat_tasks WHERE id = $1",
        )
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap()
    }

    /// The release note's example: moving the backup to 03:30 must not blank what the task sends
    /// where. Everything but `schedule` stays as it was, `next_run` resets only on a real change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_schedule_changes_only_the_schedule_and_resets_next_run_only_on_change() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_set_schedule").await else { return };
        let mut s = spec("database_backup", "research_report", json!({"topic": "keep me"}));
        s.channels = json!(["telegram"]);
        s.recipients = json!(["ops-room"]);
        s.enabled = false;
        write_task(&db, &admin(), &s, "create").await.unwrap();
        // Postgres keeps microseconds; compare like with like.
        use chrono::Timelike as _;
        let stamp = chrono::Utc::now() + chrono::Duration::hours(3);
        let stamp = stamp.with_nanosecond(stamp.nanosecond() / 1000 * 1000).unwrap();
        crate::repo::heartbeat::set_next_run(&db, "database_backup", stamp).await.unwrap();
        let before = full_row(&db, "database_backup").await;
        assert_eq!(before.7, Some(stamp));

        // unchanged schedule: next_run is kept
        let same = set_schedule(&db, &door(), "database_backup", "30 7 * * 0").await.unwrap().expect("exists");
        assert_eq!(same.old_schedule, "30 7 * * 0");
        assert!(matches!(same.written, Written::Direct { .. }));
        assert_eq!(same.next_run, Some(stamp), "same schedule keeps next_run");
        assert_eq!(full_row(&db, "database_backup").await, before);

        // a real change: schedule moves, next_run clears, nothing else moves
        let moved = set_schedule(&db, &door(), "database_backup", "30 3 * * *").await.unwrap().expect("exists");
        assert_eq!(moved.old_schedule, "30 7 * * 0");
        assert_eq!(moved.next_run, None);
        let after = full_row(&db, "database_backup").await;
        assert_eq!(after.1, "30 3 * * *");
        assert_eq!(after.7, None, "next_run cleared so the tick loop reseats it");
        assert_eq!((&after.0, &after.2, &after.3, &after.4, &after.5, after.6), (&before.0, &before.2, &before.3, &before.4, &before.5, before.6), "name/action/config/channels/recipients/enabled untouched");

        // unknown id
        assert!(set_schedule(&db, &door(), "nope", "30 3 * * *").await.unwrap().is_none());
    }

    /// The guard still applies: a destructive task's schedule is part of what a person authorised.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ai_cannot_move_a_destructive_tasks_schedule_but_a_person_can() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_set_schedule_guard").await else { return };
        write_task(&db, &admin(), &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 100})), "create").await.unwrap();
        let ch = set_schedule(&db, &door(), "clean", "* * * * *").await.unwrap().expect("exists");
        assert!(matches!(ch.written, Written::Proposed { .. }), "{ch:?}");
        assert_eq!(full_row(&db, "clean").await.1, "30 7 * * 0", "the live schedule did not move");
        assert_eq!(proposals(&db).await.len(), 1);
        let ch = set_schedule(&db, &admin(), "clean", "0 2 * * *").await.unwrap().expect("exists");
        assert!(matches!(ch.written, Written::Direct { .. }));
        assert_eq!(full_row(&db, "clean").await.1, "0 2 * * *");
    }

    #[test]
    fn the_handlers_use_the_guard_and_the_decide_route_checks_a_person() {
        let routes = include_str!("routes/intelligence.rs");
        let block = |name: &str| {
            let start = routes.find(&format!("async fn {name}(")).unwrap_or_else(|| panic!("{name}"));
            let rest = &routes[start..];
            rest[..rest.find("\n}\n").unwrap()].to_string()
        };
        for h in ["heartbeat_create_task", "heartbeat_schedule_task"] {
            assert!(block(h).contains("write_task("), "{h} writes through the guard");
            assert!(!block(h).contains("upsert_task("), "{h} does not write around it");
        }
        assert!(block("heartbeat_toggle_task").contains("set_enabled("));
        // the schedule edit validates with the scheduler's parser BEFORE it writes, and writes through the guard
        let sched = block("heartbeat_set_schedule");
        assert!(sched.contains("task_guard::set_schedule("), "writes through task_guard::set_schedule");
        assert!(!sched.contains("upsert_task("), "never rewrites the whole row");
        assert!(sched.contains("parse_cron("), "validates with the scheduler's parser");
        assert!(sched.find("parse_cron(").unwrap() < sched.find("task_guard::set_schedule(").unwrap(), "validates before writing");
        assert!(sched.contains("BadRequest") && sched.contains("NotFound"), "400 on a bad cron, 404 on an unknown task");
        assert!(block("heartbeat_run_task").contains("may_run_now("));
        // the reports folder: the guard reads the source delivery reads, and setting it needs a person
        assert!(include_str!("task_guard.rs").contains("settings::get(\"NOO_REPORTS_DRIVE_FOLDER_ID\")"));
        assert!(include_str!("heartbeat_actions.rs").contains("settings::get(\"NOO_REPORTS_DRIVE_FOLDER_ID\")"));
        let st = include_str!("routes/settings.rs");
        let set = &st[st.find("async fn settings_flags_set(").unwrap()..];
        assert!(set[..set.find("STRING_REGISTRY.iter().find").unwrap()].contains("needs_person("));
        assert!(st[st.find("pub(crate) fn needs_person(").unwrap()..].contains("EGRESS_TARGET_SETTINGS"));
        assert!(EGRESS_TARGET_SETTINGS.contains(&"NOO_REPORTS_DRIVE_FOLDER_ID"));
        let users = include_str!("routes/users.rs");
        let decide = &users[users.find("async fn proposal_decide(").unwrap()..];
        let decide = &decide[..decide.find("\n}\n").unwrap()];
        assert!(decide.contains("check_approver("), "approval re-classifies and requires a person");
        assert!(decide.contains("apply_approved("));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_an_enabled_human_account_is_a_person() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_human").await else { return };
        let root = account(&db, "root", Role::Admin).await;
        let ext = |c: RequesterCtx| Some(axum::Extension(c));
        assert!(matches!(resolve_origin(&db, &ext(root.clone())).await, Origin::Person { .. }));
        // passes the claim test, names no account
        let ghost = RequesterCtx { sub: "someone-else".into(), ..root.clone() };
        assert!(matches!(resolve_origin(&db, &ext(ghost)).await, Origin::Agent { .. }), "no such user");
        // an add-on token: sub addon:<name>, no harness, no act
        let addon = RequesterCtx { sub: "addon:evolve".into(), role: Role::Operator, ..root.clone() };
        assert!(matches!(resolve_origin(&db, &ext(addon)).await, Origin::Agent { .. }), "an add-on exchange");
        sqlx::query("UPDATE noo_users SET disabled = true WHERE username = 'root'").execute(&db).await.unwrap();
        assert!(matches!(resolve_origin(&db, &ext(root)).await, Origin::Agent { .. }), "a disabled account");
    }

    #[test]
    fn a_run_now_needs_the_role_the_task_needs() {
        let operator = Origin::Person { account: "olive".into(), role: Role::Operator };
        assert!(may_run_now(&operator, "memory_cleanup", &json!({})).is_ok());
        assert!(may_run_now(&operator, "entity_cleanup", &json!({"apply": true})).is_err(), "an Admin-authorised apply is not an Operator's to fire");
        assert!(may_run_now(&operator, "entity_cleanup", &json!({})).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ai_made_agent_turn_task_runs_with_read_only_tools_until_a_person_authorises_it() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_custom").await else { return };
        // EVERY action whose runs are agent turns: custom_prompt, channel_message (config.prompt), goal_review,
        // research (instructions), briefings, digests, news_scan, conversation_summarize
        let families: Vec<&str> = ACTION_CLASSES.iter().map(|(a, _)| *a).filter(|a| is_agent_turn_action(a)).collect();
        assert!(families.len() >= 9, "{families:?}");
        for action in &families {
            let id = format!("t_{action}");
            let conv = format!("heartbeat-{id}");
            let w = write_task(&db, &door(), &spec(&id, action, json!({"prompt": "tidy up", "message": "hi", "instructions": "x", "goals": ["a"]})), "create").await.unwrap();
            assert_eq!(w, Written::Direct { authorised_by: None }, "{action}: it keeps working, created directly");
            {
                let _c = ceiling_for_run(&db, &id, action, &conv).await.unwrap_or_else(|| panic!("{action}: limited, no person authorised it"));
                for tool in ["noo_job_cancel", "noo_scheduler_drain", "noo_heartbeat_delete_task", "noo_recall_archive", "noo_config_set", "noo_graph_entity_cleanup", "never_heard_of_it", "noo_agent_ack", "noo_task_done", "web_search", "noo_web_search", "noo_graph_navigate", "noo_channel_read_messages"] {
                    assert!(turn_tool_denied(&conv, "heartbeat", tool, &json!({})).is_some(), "{action}: {tool} is refused");
                    assert!(turn_tool_denied(&format!("{conv}-gather-1"), "heartbeat", tool, &json!({})).is_some(), "{action}: {tool} in a phase turn");
                }
                for tool in ["noo_graph_stats", "noo_rag_query", "noo_memory_search"] {
                    assert!(turn_tool_denied(&conv, "heartbeat", tool, &json!({})).is_none(), "{action}: {tool} stays");
                }
                assert!(turn_tool_denied("heartbeat-other", "heartbeat", "noo_job_cancel", &json!({})).is_none(), "another turn is untouched");
                let denied = _c.take_denied();
                assert!(!denied.is_empty());
                assert!(denied_note(&denied).contains("Read-only limit"), "the run result says it was limited");
            }
            assert!(turn_tool_denied(&conv, "heartbeat", "noo_job_cancel", &json!({})).is_none(), "the limit ends with the run");
            // a person's own write authorises it: the full tool list
            let w = write_task(&db, &admin(), &spec(&id, action, json!({"prompt": "tidy up", "message": "hi", "instructions": "x", "goals": ["a"]})), "create").await.unwrap();
            assert_eq!(w, Written::Direct { authorised_by: Some("root".into()) }, "{action}");
            assert!(ceiling_for_run(&db, &id, action, &conv).await.is_none(), "{action}");
            // an agent edit revokes it
            write_task(&db, &door(), &spec(&id, action, json!({"prompt": "tidy up more", "message": "hi", "instructions": "x", "goals": ["a"]})), "create").await.unwrap();
            assert!(task_row(&db, &id).await.unwrap().3.is_none(), "{action}: revoked");
            assert!(ceiling_for_run(&db, &id, action, &conv).await.is_some(), "{action}: limited again");
        }
        // actions that are not agent turns are not limited
        assert!(ceiling_for_run(&db, "x", "cluster_health", "heartbeat-x").await.is_none());
        let src = include_str!("tools.rs");
        let exec = &src[src.find("pub async fn execute_tool(").unwrap()..];
        assert!(exec[..exec.find("before_tool_call").unwrap()].contains("turn_tool_denied("), "execute_tool checks the ceiling before any tool runs");
        let ha = include_str!("heartbeat_actions.rs");
        let run = &ha[ha.find("pub async fn run_llm_action(").unwrap()..];
        assert!(run[..run.find("run_llm_action_inner(").unwrap()].contains("ceiling_for_run("));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proposal_is_void_if_the_task_changed_and_needs_the_role_of_old_and_new() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_base").await else { return };
        write_task(&db, &admin(), &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 10})), "create").await.unwrap();
        write_task(&db, &door(), &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 20})), "create").await.unwrap();
        let payload = proposals(&db).await[0].1.clone();
        // a person edits the live task meanwhile
        write_task(&db, &admin(), &spec("clean", "entity_cleanup", json!({"apply": true, "max_delete": 30})), "create").await.unwrap();
        let mut tx = db.begin().await.unwrap();
        let err = apply_approved(&mut tx, &payload, &admin()).await.unwrap_err();
        assert!(err.contains("changed after this proposal"), "{err}");
        tx.rollback().await.unwrap();
        assert_eq!(task_row(&db, "clean").await.unwrap().1["max_delete"], 30, "nothing was written");
        // the role of the OLD spec counts: an Operator cannot take over an Admin-level task by approving a safe edit
        let operator = Origin::Person { account: "olive".into(), role: Role::Operator };
        write_task(&db, &door(), &spec("clean", "entity_cleanup", json!({"apply": false})), "create").await.unwrap();
        let payload = proposals(&db).await.last().unwrap().1.clone();
        let mut tx = db.begin().await.unwrap();
        assert!(apply_approved(&mut tx, &payload, &operator).await.is_err(), "the live task needs an Admin");
        tx.rollback().await.unwrap();
        let mut tx = db.begin().await.unwrap();
        apply_approved(&mut tx, &payload, &admin()).await.unwrap();
        tx.commit().await.unwrap();
        // an agent cannot approve at all
        let mut tx = db.begin().await.unwrap();
        assert!(apply_approved(&mut tx, &payload, &door()).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identical_pending_proposals_collapse_and_created_by_comes_from_the_token() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_dedupe").await else { return };
        let mut s = spec("convs", "memory_cleanup", json!({}));
        s.created_by = "root".into(); // the request body claims to be root
        let first = write_task(&db, &door(), &s, "create").await.unwrap();
        let second = write_task(&db, &door(), &s, "create").await.unwrap();
        let (Written::Proposed { proposal_id: a, .. }, Written::Proposed { proposal_id: b, .. }) = (first, second) else { panic!() };
        assert_eq!(a, b, "the same request is one proposal");
        assert_eq!(proposals(&db).await.len(), 1);
        assert_eq!(proposals(&db).await[0].1["task"]["created_by"], "agent", "the credential decides, not the body");
        // a different spec is its own proposal
        let mut other = spec("convs", "memory_cleanup", json!({"max_age_days": 5}));
        other.created_by = "root".into();
        write_task(&db, &door(), &other, "create").await.unwrap();
        assert_eq!(proposals(&db).await.len(), 2);
        // a direct write records the writer, whatever the body says
        let mut r = spec("rep", "research_report", json!({}));
        r.created_by = "root".into();
        write_task(&db, &door(), &r, "create").await.unwrap();
        let by: String = sqlx::query_scalar("SELECT created_by FROM noo_heartbeat_tasks WHERE id = 'rep'").fetch_one(&db).await.unwrap();
        assert_eq!(by, "agent");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_non_person_may_send_only_to_targets_a_person_registered() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_targets").await else { return };
        let mut s = spec("digest", "channel_message", json!({"message": "hi", "drive_folder_id": "folderX"}));
        s.recipients = json!(["spaces/AAAA"]);
        s.channels = json!(["google_chat"]);
        // new recipient and new folder: a proposal
        let Written::Proposed { why, .. } = write_task(&db, &door(), &s, "create").await.unwrap() else { panic!() };
        assert!(why.contains("not registered"), "{why}");
        assert!(task_row(&db, "digest").await.is_none());
        // EVERY action delivers its result to its recipients: a briefing is no different
        let mut b = spec("brief", "daily_briefing", json!({}));
        b.recipients = json!(["spaces/EVIL"]);
        b.channels = json!(["google_chat"]);
        assert!(matches!(write_task(&db, &door(), &b, "create").await.unwrap(), Written::Proposed { .. }), "daily_briefing to a new recipient");
        let mut c = spec("health", "cluster_health", json!({}));
        c.recipients = json!(["spaces/EVIL"]);
        assert!(matches!(write_task(&db, &door(), &c, "create").await.unwrap(), Written::Proposed { .. }), "cluster_health to a new recipient");
        // a person may; the target is then registered (it is on a task a person authorised)
        assert!(matches!(write_task(&db, &admin(), &s, "create").await.unwrap(), Written::Direct { .. }));
        let mut t = spec("digest2", "research_and_send", json!({"topic": "x", "drive_folder_id": "folderX"}));
        t.recipients = json!(["spaces/AAAA"]);
        assert!(matches!(write_task(&db, &door(), &t, "create").await.unwrap(), Written::Direct { .. }), "a registered target");
        let mut h = spec("health2", "cluster_health", json!({}));
        h.recipients = json!(["spaces/AAAA"]);
        assert!(matches!(write_task(&db, &door(), &h, "create").await.unwrap(), Written::Direct { .. }));
        // a target that is only on a task AN AGENT made is not registered, so it cannot launder another
        let mut m = spec("agent_made", "research_report", json!({}));
        m.recipients = json!(["spaces/LAUNDER"]);
        assert!(matches!(write_task(&db, &door(), &m, "create").await.unwrap(), Written::Proposed { .. }));
        assert!(task_row(&db, "agent_made").await.is_none());
        sqlx::query("INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled, recipients) VALUES ('legacy', 'l', '0 1 * * *', 'cluster_health', '{}', true, '[\"spaces/OLD\"]')").execute(&db).await.unwrap();
        let mut o = spec("uses_old", "cluster_health", json!({}));
        o.recipients = json!(["spaces/OLD"]);
        assert!(matches!(write_task(&db, &door(), &o, "create").await.unwrap(), Written::Proposed { .. }), "a task with no recorded person registers nothing");
        // saved recipients count only when a person created them
        sqlx::query("INSERT INTO noo_channel_recipients (id, channel, recipient_id, display_name) VALUES ('r0', 'telegram', '777', 'unknown author')").execute(&db).await.unwrap();
        sqlx::query("INSERT INTO noo_channel_recipients (id, channel, recipient_id, display_name, created_by) VALUES ('r1', 'telegram', '12345', 'me', 'root')").execute(&db).await.unwrap();
        let mut u = spec("digest3", "channel_message", json!({"message": "hi"}));
        u.recipients = json!(["12345"]);
        assert!(matches!(write_task(&db, &door(), &u, "create").await.unwrap(), Written::Direct { .. }));
        let mut v = spec("digest4", "channel_message", json!({"message": "hi"}));
        v.recipients = json!(["777"]);
        assert!(matches!(write_task(&db, &door(), &v, "create").await.unwrap(), Written::Proposed { .. }), "no recorded author");
        let comm = include_str!("routes/communication.rs");
        let create = &comm[comm.find("async fn create_saved_recipient(").unwrap()..];
        assert!(create[..create.find("\n}\n").unwrap()].contains("resolve_origin("), "the saved-recipient write records a person");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deleting_a_task_keeps_its_run_history() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_runs").await else { return };
        write_task(&db, &door(), &spec("rep", "research_report", json!({})), "create").await.unwrap();
        let now = chrono::Utc::now();
        let empty = json!([]);
        crate::repo::heartbeat::record_run(
            &db,
            &crate::repo::heartbeat::RunRecord {
                run_id: "run1", task_id: "rep", task_name: "rep", action: "research_report", started_at: now, completed_at: now,
                status: "success", result_text: "x", error: None, duration_ms: 1, notified_channels: &empty, artifacts: &empty,
            },
        )
        .await
        .unwrap();
        assert_eq!(crate::repo::heartbeat::delete_task(&db, "rep").await.unwrap(), 1);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM noo_heartbeat_runs WHERE task_id = 'rep'").fetch_one(&db).await.unwrap();
        assert_eq!(n, 1, "an agent cannot erase a task's history by deleting the task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn existing_tasks_and_recipients_wait_for_a_person_who_approves_them_one_by_one() {
        let _serial = DB_LOCK.lock().await;
        let Some(db) = scratch("tg_review").await else { return };
        // pre-guard rows: no recorded person
        for (id, action) in [("old_research", "research_report"), ("old_prompt", "custom_prompt"), ("old_clean", "memory_cleanup"), ("old_health", "cluster_health")] {
            sqlx::query("INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled) VALUES ($1, $1, '0 1 * * *', $2, '{}', true)")
                .bind(id).bind(action).execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO noo_heartbeat_tasks (id, name, schedule, action, config, enabled, recipients) VALUES ('old_health_to', 'x', '0 1 * * *', 'cluster_health', '{}', true, '[\"spaces/A\"]')").execute(&db).await.unwrap();
        sqlx::query("INSERT INTO noo_channel_recipients (id, channel, recipient_id, display_name) VALUES ('r1', 'telegram', '1', 'me')").execute(&db).await.unwrap();
        let (tasks, recips) = pending_review(&db).await.unwrap();
        let ids: Vec<&str> = tasks.iter().map(|t| t["id"].as_str().unwrap()).collect();
        // the seeded dry-run cleanup and a plain health check (no targets) need no record; the seeded
        // retention task is destructive and has no recorded person, so it waits too
        assert_eq!(ids, ["agent_messages_retention", "old_clean", "old_health_to", "old_prompt", "old_research"], "{ids:?}");
        assert_eq!(recips.len(), 1);
        assert_eq!(review_count(&db).await, 6);
        // a door cannot approve; an Operator approves the Operator-level ones
        assert_eq!(approve_review(&db, &door(), &["old_prompt".into()], &[]).await.unwrap().0, 0);
        let op = Origin::Person { account: "olive".into(), role: Role::Operator };
        let (t, r, skipped) = approve_review(&db, &op, &["old_prompt".into(), "old_clean".into(), "nope".into()], &["r1".into()]).await.unwrap();
        assert_eq!((t, r), (2, 1), "{skipped:?}");
        assert_eq!(skipped.len(), 1);
        let by: Option<String> = sqlx::query_scalar("SELECT authorised_by FROM noo_heartbeat_tasks WHERE id = 'old_prompt'").fetch_one(&db).await.unwrap();
        assert_eq!(by.as_deref(), Some("olive"), "recorded as the person who approved it");
        let cb: Option<String> = sqlx::query_scalar("SELECT created_by FROM noo_channel_recipients WHERE id = 'r1'").fetch_one(&db).await.unwrap();
        assert_eq!(cb.as_deref(), Some("olive"));
        // approved items run with the full tool list and the recipient is registered
        assert!(ceiling_for_run(&db, "old_prompt", "custom_prompt", "heartbeat-old_prompt").await.is_none());
        assert!(ceiling_for_run(&db, "old_research", "research_report", "heartbeat-old_research").await.is_some(), "not yet reviewed");
        assert_eq!(review_count(&db).await, 3);
        approve_review(&db, &admin(), &["old_research".into(), "old_health_to".into(), "agent_messages_retention".into()], &[]).await.unwrap();
        assert_eq!(review_count(&db).await, 0);
    }
}
