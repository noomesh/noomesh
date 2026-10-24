// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! DB-authoritative security posture for the app-tier gates (PR: Part 2).
//!
//! At boot, [`apply_security_posture`] reads `noo_security_posture` and overrides
//! the process env for the known app-tier gate keys, BEFORE the server accepts
//! traffic — so the read-once gate accessors capture the DB value. A customer's posture therefore lives in the DB
//! (operator-managed, audited, restart-to-apply) with `.env` as the bootstrap
//! fallback, rather than a hand-edited env file.
//!
//! Bootstrap-tier gates (TLS, secrets — needed *before* the DB is reachable)
//! are NOT here; those stay in the secrets backend.

use crate::audit::{AuditEvent, AuditKind};
use sqlx::PgPool;

/// What a posture key IS — and therefore whether a vetted profile may set it.
///
/// The distinction is not cosmetic. It came out of a live rollout: applying
/// `hardened` at runbook step C1 set `NOO_NATS_LEGACY_SHARED_CREDS` (a bus
/// bridge since retired) back to 0, undoing step A3 two parts
/// earlier, and took a Mac node off the bus until the
/// bridge was put back by hand. A profile describes an environment;
/// it must not decide where an operator is in a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureKind {
    /// A standing property of the installation — "is the external MCP door
    /// open", "do HIGH-risk tools need a human". A vetted profile SETS these:
    /// that is what a profile is for, and every profile must cover every one
    /// of them (`tests/test_posture_key_parity.py`).
    Gate,
    /// A compatibility bridge the operator is deliberately holding open while
    /// a fleet crosses a version boundary. A profile must NEVER name one:
    /// whether the bridge is open is a fact about *this afternoon*, not about
    /// the environment, and only the operator knows whether the last node has
    /// crossed. `apply-profile` leaves these untouched and says so;
    /// `--include-bridges` closes them to `closed`.
    Bridge {
        /// The value that CLOSES this bridge — what `--include-bridges` writes.
        /// A bridge always has a safe direction; this names it, so the closing
        /// value lives with the key instead of being duplicated per profile.
        closed: &'static str,
        /// How long this bridge is expected to stay open, in days, from the
        /// moment it was opened. It lives on the key for the same reason
        /// `closed` does: a window duplicated per profile, per runbook or per
        /// operator's memory is a window that drifts, and every one of these
        /// has drifted at least once.
        ///
        /// This is an EXPECTATION, not an enforcement. Nothing closes a bridge
        /// on this date — the fleet decides that, and closing one early is how
        /// R43 took a Mac off the bus. What the date does is make an
        /// unaccounted-for bridge impossible to read as fine.
        window_days: i64,
    },
}

impl PostureKind {
    pub fn is_bridge(self) -> bool {
        matches!(self, PostureKind::Bridge { .. })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            PostureKind::Gate => "gate",
            PostureKind::Bridge { .. } => "bridge",
        }
    }
}

/// One app-tier posture key: its name, what it is, and one line an operator
/// can read in `noo security posture list` without opening the source.
#[derive(Debug, Clone, Copy)]
pub struct PostureKey {
    pub key: &'static str,
    pub kind: PostureKind,
    /// One line, operator-facing. Printed by the CLI, so keep it short.
    pub why: &'static str,
}

/// THE app-tier posture allow-list, classified. An allow-list, so a stray
/// `noo_security_posture` row can never set an arbitrary process env var.
///
/// Single source of truth: [`posture_keys`], [`is_posture_key`] and
/// [`kind_of`] all read this, and `routes::users::posture_profile` is checked
/// against it by the parity test. There is deliberately no second flat list to
/// drift out of step with it.
///
/// Removed over time, and why, so nobody re-adds them: `NOO_MULTI_USER`
/// (tenant isolation is unconditional — `auth::scoped_user` applies on every
/// HTTP call and an unattributed worker read resolves a scope or fails
/// closed); `NOO_AUTH_ENABLED` / `NOO_CLUSTER_AUTH_STRICT` (auth and strict
/// cluster-token verification are invariants, always on, fail-closed).
pub const POSTURE_CATALOG: &[PostureKey] = &[
    PostureKey {
        key: "NOO_EXEC_APPROVAL_MODE",
        kind: PostureKind::Gate,
        why: "whether HIGH-risk tool calls need a human (auto | approval | strict)",
    },
    PostureKey {
        key: "NOO_NODE_AGENT_PRIVILEGED",
        kind: PostureKind::Gate,
        why: "whether the node-agent container runs privileged",
    },
    // An app-tier gate deciding who may reach the cluster's tools, so it
    // belongs under operator-managed, audited, allow-listed posture.
    // Deliberately NOT noomesh.yaml — `noo config set` is reachable by any
    // write-scope user, who could then open this door on themselves.
    PostureKey {
        key: "NOO_MCP_EXTERNAL_ENABLED",
        kind: PostureKind::Gate,
        why: "opens the user MCP door (/mcp/user) to third-party agents",
    },
    // `NOO_APPROVAL_BREAK_GLASS` was a gate here (a shared-secret caller with
    // no RequesterCtx deciding exec approvals) until it was retired: it is in
    // RETIRED_BRIDGES below, so a row or env value still holding it open
    // refuses boot instead of being silently ignored.
    // `NOO_SELF_CALL_SHARED_SECRET` was a bridge here (a shared-secret HMAC
    // buying inference) until it was retired: the fleet door refuses the
    // inference surface unconditionally (`auth.rs`, counted as
    // `self_call_shared_secret_refused`) and the controller door admits
    // nothing. Nothing reads the flag any more. It is a RETIRED_INERT_KEYS
    // entry: boot deletes a stale row at a closed value and warns about one
    // still set open (it is not a retired-bridge boot refusal: there is
    // nothing left to hold open).
    //
    // `NOO_CONTROLLER_SECRET` is not retired by this: its one remaining job
    // is the gateway's boot guard (no controller secret, no start).
    // The v1 cluster token (HMAC over actor and time only) is a
    // replayable bearer; v2 binds the request. Every verifier accepts both
    // while the fleet rolls and counts v1 under the `cluster_hmac_v1` lane
    // (`noo cluster verify` names the callers). "0" refuses v1 at the gateway
    // door and, mirrored to the agent env, at each node. Unlike the other
    // bridges this one is OPEN when unset, because every install's nodes sign
    // v1 until they upgrade; it is closed deliberately, once, after the roll.
    PostureKey {
        key: "NOO_CLUSTER_TOKEN_V1",
        kind: PostureKind::Bridge { closed: "0", window_days: 60 },
        why: "keeps accepting the old replayable cluster token from nodes that have not upgraded",
    },
    // `NOO_NATS_LEGACY_SHARED_CREDS` was a bridge here (the one R43 was about)
    // retired the shared bus user it bridged to: the server
    // no longer defines that user, so there is nothing left to hold open.
    // A stale row in `noo_security_posture` is now an unknown key, which
    // `apply_security_posture` skips; `noo cluster verify --controller` FAILs
    // while one is still set anywhere.
    // Retired bridges live in RETIRED_BRIDGES below, not here: a row still
    // holding one open is a boot refusal, never a silently ignored key.
];

/// Every posture key name, in catalog order.
pub fn posture_keys() -> impl Iterator<Item = &'static str> {
    POSTURE_CATALOG.iter().map(|k| k.key)
}

/// Is `key` an app-tier posture key at all? The allow-list check.
pub fn is_posture_key(key: &str) -> bool {
    POSTURE_CATALOG.iter().any(|k| k.key == key)
}

/// The catalog entry for `key`, if it is one.
pub fn entry_of(key: &str) -> Option<&'static PostureKey> {
    POSTURE_CATALOG.iter().find(|k| k.key == key)
}

/// Gate or bridge? `None` for a key that is not posture-managed.
pub fn kind_of(key: &str) -> Option<PostureKind> {
    entry_of(key).map(|k| k.kind)
}

/// The GATE keys — the ones a vetted profile must cover.
pub fn gate_keys() -> impl Iterator<Item = &'static str> {
    POSTURE_CATALOG
        .iter()
        .filter(|k| !k.kind.is_bridge())
        .map(|k| k.key)
}

/// The BRIDGE keys — the ones a profile must never name.
pub fn bridge_keys() -> impl Iterator<Item = &'static PostureKey> {
    POSTURE_CATALOG.iter().filter(|k| k.kind.is_bridge())
}

/// A compatibility bridge that has been RETIRED: its arm is deleted from the
/// code, so no value of it changes behaviour any more.
///
/// It is not simply dropped from [`POSTURE_CATALOG`], because an install can
/// still carry a row (or an env value) holding it OPEN — an operator
/// mid-migration who believes the bridge is doing something. Ignoring that
/// row would leave them with a compatibility window that exists only in their
/// head, so the gateway REFUSES TO START while one is open
/// ([`retired_bridge_refusal`]), naming the key and the one command that
/// clears it. A row at the closed value is fine and is left alone.
#[derive(Debug, Clone, Copy)]
pub struct RetiredBridge {
    pub key: &'static str,
    /// The closing value — what `noo security posture set <key> <closed>`
    /// may still write, so an operator can clear the refusal without SQL.
    pub closed: &'static str,
    /// What happens now that the arm is gone. Operator-facing, one line.
    pub now: &'static str,
}

pub const RETIRED_BRIDGES: &[RetiredBridge] = &[
    // Every install mints NOO_CONTROLLER_SECRET; a
    // gateway without it refuses to start (`auth::boot_refusal`), and a
    // fleet-secret token is only ever a Node.
    RetiredBridge {
        key: "NOO_CLUSTER_LEGACY_FULL_ACCESS",
        closed: "0",
        now: "a fleet-secret token is only ever a node; NOO_CONTROLLER_SECRET is required",
    },
    // Every node's noo-fetch signs its receipt with the birth
    // key; an unsigned write on the provisioning pull lane is refused.
    RetiredBridge {
        key: "NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH",
        closed: "0",
        now: "an unsigned fetch receipt / apply report on the pull lane is refused",
    },
    // Workers verify the signed Noo-Principal header on
    // every worker.* message; there is no unsigned mode.
    RetiredBridge {
        key: "NOO_BUS_PRINCIPAL",
        closed: "required",
        now: "workers always require a verified Noo-Principal on worker.* messages",
    },
    // Was a posture GATE, not a bridge: with it on, a shared-secret caller
    // with no RequesterCtx decided exec approvals as
    // `cli-operator:break-glass`. Closed in both vetted profiles, and the
    // CLI stopped holding a shared secret, so the arm only ever served a
    // non-CLI holder of the controller secret. Retired, not dropped: an
    // operator who opened it for a lock-out believes a recovery door is
    // there, and must be told at boot that it is not. The recovery for a
    // lost login is `noo security admin-password reset` on the controller.
    RetiredBridge {
        key: "NOO_APPROVAL_BREAK_GLASS",
        closed: "0",
        now: "approval decisions always take a named operator login; a shared-secret caller is refused",
    },
];

/// The retired-bridge entry for `key`, if it is one.
pub fn retired_bridge(key: &str) -> Option<&'static RetiredBridge> {
    RETIRED_BRIDGES.iter().find(|b| b.key == key)
}

/// Would `value` have held this retired bridge OPEN when its arm existed?
///
/// Per key, because each arm read its flag differently, and refusing a value
/// the old arm treated as CLOSED would brick a boot over a safe row:
/// `NOO_CLUSTER_LEGACY_FULL_ACCESS` opened on a truthy value only;
/// `NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH` on anything but "0";
/// `NOO_BUS_PRINCIPAL` on "optional" only; `NOO_APPROVAL_BREAK_GLASS` on
/// exactly "1", "true", "TRUE", "yes" or "on" (its arm compared the raw value,
/// so " 1" or "Yes" was closed there and is closed here). Unset/empty is
/// never open here — an install that never wrote the row has nothing to
/// account for.
pub fn retired_value_opens(key: &str, value: &str) -> bool {
    if key == "NOO_APPROVAL_BREAK_GLASS" {
        return matches!(value, "1" | "true" | "TRUE" | "yes" | "on");
    }
    let v = value.trim().to_ascii_lowercase();
    if v.is_empty() {
        return false;
    }
    match key {
        "NOO_CLUSTER_LEGACY_FULL_ACCESS" => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
        "NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH" => v != "0",
        "NOO_BUS_PRINCIPAL" => v == "optional",
        _ => false,
    }
}

/// Retired posture keys that never became a [`RetiredBridge`] — their
/// arm went with the thing they bridged to, so no value changes anything and
/// no boot refusal guards them. `NOO_NATS_LEGACY_SHARED_CREDS`: the server no longer defines the shared bus user it opened.
/// `NOO_SELF_CALL_SHARED_SECRET`: the self-call bridge is deleted; a shared secret never buys inference.
pub const RETIRED_INERT_KEYS: &[&str] = &["NOO_NATS_LEGACY_SHARED_CREDS", "NOO_SELF_CALL_SHARED_SECRET"];

/// Does `value` read as ON for a [`RETIRED_INERT_KEYS`] row? Such a row is
/// never deleted at boot (the operator believed something was open); it is
/// reported instead, with the one write that closes it.
fn inert_value_on(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// The [`RETIRED_INERT_KEYS`] rows still set ON: boot keeps them and warns
/// (`noo security posture set <key> 0`, then the next start deletes the
/// row). Pure, so the choice is tested.
pub fn retired_inert_rows_held_open(rows: &[(String, String)]) -> Vec<(String, String)> {
    rows.iter()
        .filter(|(k, v)| RETIRED_INERT_KEYS.contains(&k.as_str()) && inert_value_on(v))
        .cloned()
        .collect()
}

/// The posture rows boot DELETES: a retired key (a [`RetiredBridge`] or a
/// [`RETIRED_INERT_KEYS`] entry) holding a value that does NOT open it. Such
/// a row is inert, and the only thing it ever did after retirement was keep
/// `noo cluster verify --controller` at WARN with a raw `psql DELETE` as the
/// remedy — no `noo` verb could clear it. A row holding a retired bridge OPEN is
/// never deleted: that is the boot refusal's to report, because the
/// operator believes something is open. Pure, so the choice is tested.
pub fn retired_rows_to_clear(rows: &[(String, String)]) -> Vec<(String, String)> {
    rows.iter()
        .filter(|(k, v)| {
            if retired_bridge(k).is_some() {
                return !retired_value_opens(k, v);
            }
            RETIRED_INERT_KEYS.contains(&k.as_str()) && !inert_value_on(v)
        })
        .cloned()
        .collect()
}

/// Delete the [`retired_rows_to_clear`] rows, each with a tamper-evident
/// audit event. Best effort: a failure is logged and the row stays (inert).
async fn clear_retired_rows(db: &PgPool, rows: &[(String, String)]) {
    for (key, value) in retired_rows_to_clear(rows) {
        let deleted = sqlx::query("DELETE FROM noo_security_posture WHERE key = $1 AND value = $2")
            .bind(&key)
            .bind(&value)
            .execute(db)
            .await;
        match deleted {
            Ok(r) if r.rows_affected() > 0 => {
                crate::audit::record(
                    db,
                    AuditEvent::new(AuditKind::SecurityPostureRetiredRowRemoved, "gateway-boot", &key)
                        .details(serde_json::json!({ "key": key, "value": value, "why": "retired key at a closed value — inert" })),
                )
                .await;
                tracing::info!(key = %key, value = %value,
                    "removed a retired posture row at its closed value (inert; nothing changes)");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(key = %key, error = %e,
                "could not remove a retired posture row at its closed value — it stays, inert"),
        }
    }
}

/// Posture-table rows naming a retired bridge, captured by
/// [`apply_security_posture`] for [`retired_bridge_refusal`]. The table is
/// read exactly once, at boot, so the capture is the evidence.
static RETIRED_ROWS: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// The refusal, pure: `found` is `(key, value, where)` for every place a
/// retired bridge was set. `Some(message)` = do not start.
pub fn retired_bridge_refusal_for(found: &[(&str, &str, &str)]) -> Option<String> {
    let lines: Vec<String> = found
        .iter()
        .filter(|(k, v, _)| retired_value_opens(k, v))
        .filter_map(|(k, v, src)| {
            let b = retired_bridge(k)?;
            Some(format!(
                "  {k}={v} ({src}) — this bridge is RETIRED; {now}. Clear it: \
                 `noo security posture set {k} {closed}` and remove {k} from the controller \
                 env, then restart",
                now = b.now,
                closed = b.closed,
            ))
        })
        .collect();
    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "a RETIRED compatibility bridge is still set open, and its code path no longer \
         exists — refusing to start rather than run a bridge the operator believes is \
         open:\n{}",
        lines.join("\n")
    ))
}

/// Boot refusal for a retired bridge left open in the posture table (captured
/// at [`apply_security_posture`]) or in this process's environment. Checked
/// after the posture pass, like `auth::boot_refusal`.
pub fn retired_bridge_refusal() -> Option<String> {
    let rows = RETIRED_ROWS.lock().map(|r| r.clone()).unwrap_or_default();
    let env: Vec<(String, String)> = RETIRED_BRIDGES
        .iter()
        .filter_map(|b| std::env::var(b.key).ok().map(|v| (b.key.to_string(), v)))
        .collect();
    let mut found: Vec<(&str, &str, &str)> = Vec::new();
    for (k, v) in &rows {
        found.push((k, v, "noo_security_posture row"));
    }
    for (k, v) in &env {
        found.push((k, v, "environment"));
    }
    retired_bridge_refusal_for(&found)
}

/// Where one open bridge stands against its declared window.
///
/// `opened` is the best available evidence, not necessarily the truth: a row
/// written before migration 074 has no `opened_at`, so the caller falls back
/// to `updated_at` and [`BridgeStanding::dated_from_update`] says so. The
/// alternative — treating an unknown open date as "opened now" — would restart
/// the clock on exactly the bridges most worth expiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeStanding {
    pub key: &'static str,
    pub value: String,
    pub open_days: i64,
    pub window_days: i64,
    pub dated_from_update: bool,
}

impl BridgeStanding {
    pub fn overdue_days(&self) -> i64 {
        self.open_days - self.window_days
    }
    pub fn is_overdue(&self) -> bool {
        self.overdue_days() > 0
    }
}

/// Classify one posture row. `None` unless the key is a bridge that is
/// actually OPEN — a bridge sitting at its closed value is not a bridge the
/// operator owes anyone an account of, and reporting it would train people to
/// read past this line.
pub fn bridge_standing(
    key: &str,
    value: &str,
    open_days: i64,
    dated_from_update: bool,
) -> Option<BridgeStanding> {
    let entry = entry_of(key)?;
    let PostureKind::Bridge { closed, window_days } = entry.kind else {
        return None;
    };
    if value == closed {
        return None;
    }
    // The v1-token bridge is judged with the gateway's own reader too: any
    // closing spelling ("false", "off", …) closes it.
    if entry.key == "NOO_CLUSTER_TOKEN_V1" && !crate::cluster_token_v2::v1_allowed_value(value) {
        return None;
    }
    Some(BridgeStanding {
        key: entry.key,
        value: value.to_string(),
        open_days,
        window_days,
        dated_from_update,
    })
}

/// Load the DB posture and override the process env for known gate keys.
/// Called once at startup (DB ready, before serving). Never fails startup —
/// a missing table / DB error just leaves env (`.env`) as the posture.
pub async fn apply_security_posture(db: &PgPool) {
    // `opened_at` is preferred and `updated_at` is the fallback; COALESCE does
    // that in one expression, and the third column records WHICH one answered
    // so the log can say whether the age is evidence or inference.
    // `::float8` is load-bearing. On PostgreSQL 14+ `EXTRACT` returns
    // NUMERIC, not double precision, and dividing by `86400.0` keeps it
    // NUMERIC; sqlx refuses to decode NUMERIC into f64. Without the cast
    // this SELECT fails on every modern Postgres, and because it is the
    // boot-time apply, EVERY posture gate silently stays at its default —
    // the MCP user door came up closed after the v0.2.48 recreate and
    // `noo security posture list` returned 500, which is how it was found.
    // `every_epoch_extract_is_cast` pins the class.
    let rows = sqlx::query_as::<_, (String, String, Option<f64>, bool)>(
        "SELECT key, value, \
                (EXTRACT(EPOCH FROM (NOW() - COALESCE(opened_at, updated_at))) / 86400.0)::float8, \
                (opened_at IS NULL) \
         FROM noo_security_posture",
    )
    .fetch_all(db)
    .await;
    match rows {
        Ok(rows) => {
            let pairs: Vec<(String, String)> = rows.iter().map(|(k, v, ..)| (k.clone(), v.clone())).collect();
            clear_retired_rows(db, &pairs).await;
            for (key, value) in retired_inert_rows_held_open(&pairs) {
                tracing::warn!(key = %key, value = %value,
                    "a RETIRED posture row is still set on: nothing reads it, so it changes nothing. \
                     Close it with `noo security posture set {} 0`; the next gateway start deletes the row", key);
            }
            let mut applied = 0u32;
            let mut open_bridges: Vec<BridgeStanding> = Vec::new();
            for (key, value, age_days, from_update) in rows {
                if retired_bridge(&key).is_some() {
                    if let Ok(mut r) = RETIRED_ROWS.lock() {
                        r.push((key.clone(), value.clone()));
                    }
                }
                if is_posture_key(&key) {
                    // Safe: single-threaded startup, before any gate is read.
                    std::env::set_var(&key, &value);
                    applied += 1;
                    tracing::info!(gate = %key, "security_posture_applied_from_db");
                }
                if let Some(b) = bridge_standing(
                    &key,
                    &value,
                    age_days.unwrap_or(0.0) as i64,
                    from_update,
                ) {
                    open_bridges.push(b);
                }
            }
            if applied > 0 {
                tracing::info!(
                    count = applied,
                    "security posture loaded from DB (overrides .env)"
                );
            }
            report_open_bridges(&open_bridges);
        }
        Err(e) => {
            // A table that is not there yet is a fresh install mid-bootstrap
            // and is quiet on purpose. Anything else means the table EXISTS
            // and could not be read — every gate an operator set in the DB
            // is silently at its default — and that was logged at DEBUG
            // when v0.2.48 shipped a NUMERIC/f64 decode failure. Nobody
            // saw it until `noo security posture list` returned 500.
            let msg = e.to_string();
            if msg.contains("does not exist") {
                tracing::debug!(error = %msg, "security_posture table absent — using env/.env");
            } else {
                tracing::error!(
                    error = %msg,
                    "security_posture UNREADABLE — every DB posture gate is at its default; \
                     `noo security posture list` will fail the same way"
                );
            }
        }
    }
}

/// Config keys that USED to be read from `noomesh.yaml` and are now
/// posture-only (`<section>`, `<key>`, `<posture gate>`).
///
/// Keeping them readable would be the bug names: `noomesh.yaml` is
/// writable over `PUT /api/config/{section}`, which the agent's own
/// `noo_config_set` tool reaches, so a gate stored there can be flipped by the
/// thing it constrains. Ignoring them silently would be worse than either: an
/// operator who writes `exec_approval_mode: strict` and gets `auto` has a
/// security control that exists only in their head.
///
/// So the gateway REFUSES TO START while one is present. That is the same
/// treatment `auth::boot_refusal` already gives the controller-secret gap, and
/// the same reason: serving with a security decision we cannot honour is worse
/// than not serving. The message names the exact two commands that fix it.
pub const RETIRED_YAML_GATES: &[(&str, &str, &str)] =
    &[("security", "exec_approval_mode", "NOO_EXEC_APPROVAL_MODE")];

/// Boot refusal for a `noomesh.yaml` that still carries a retired gate key.
/// `Some(message)` = do not start. Pure function over the parsed document so
/// it is unit-testable without a gateway.
pub fn yaml_gate_refusal(config_yaml: &serde_json::Value) -> Option<String> {
    let mut found: Vec<String> = Vec::new();
    for (section, key, gate) in RETIRED_YAML_GATES {
        if config_yaml
            .get(section)
            .and_then(|s| s.get(key))
            .is_some_and(|v| !v.is_null())
        {
            found.push(format!(
                "  {section}.{key} — remove it from noomesh.yaml, then: \
                 noo security posture set {gate} <value>"
            ));
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(format!(
        "noomesh.yaml still sets security gates that are now POSTURE-ONLY, and \
         a value there would be silently ignored — refusing to start rather \
         than run a gate the operator believes is set:\n{}\n\
         Posture is read once at gateway start; `noo security posture list` \
         shows running vs desired.",
        found.join("\n")
    ))
}

/// Say, at every boot, which compatibility bridges are open and how long they
/// have been. An overdue one WARNs and names the command that closes it.
///
/// Deliberately not a refusal to start. 186a argued the escalation has to be
/// gradual: a bridge that hard-fails on day one of a slipped rollout is a
/// bridge operators learn to extend pre-emptively, which is memory again — and
/// a controller that refuses to boot over a compatibility window is an outage
/// caused by a warning. A refusal tier can land once these dates have been
/// walked once for real.
fn report_open_bridges(open: &[BridgeStanding]) {
    if open.is_empty() {
        return;
    }
    for b in open {
        let basis = if b.dated_from_update {
            " (age from updated_at — this row predates the opened_at column)"
        } else {
            ""
        };
        if b.is_overdue() {
            tracing::warn!(
                bridge = %b.key,
                value = %b.value,
                open_days = b.open_days,
                window_days = b.window_days,
                overdue_days = b.overdue_days(),
                "COMPATIBILITY BRIDGE OVERDUE — open {} days against a {}-day window{}. \
                 Close it with `noo security posture set {} <closed value>` once the fleet \
                 has crossed; `noo security posture list` shows the evidence.",
                b.open_days, b.window_days, basis, b.key,
            );
        } else {
            tracing::info!(
                bridge = %b.key,
                value = %b.value,
                open_days = b.open_days,
                window_days = b.window_days,
                "compatibility bridge open, {} of {} days{}",
                b.open_days, b.window_days, basis,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    /// `EXTRACT(EPOCH …)` returns NUMERIC on PostgreSQL 14+, and sqlx will
    /// not decode NUMERIC into f64 or i64. Every such read in the crate
    /// must cast explicitly. The one that did not — the boot-time posture
    /// apply — shipped in v0.2.48 and silently left every DB posture gate
    /// at its default; `noo security posture list` returning 500 is how
    /// the operator found it.
    ///
    /// The whole crate, walked at test time, because nothing in CI could
    /// have seen this: sqlx-drift checks `query!` macros and this was a
    /// `query_as`, and the failure only shows against a real Postgres.
    #[test]
    fn every_epoch_extract_in_the_crate_is_cast() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).expect("read src tree") {
                let p = e.expect("dir entry").path();
                if p.is_dir() { walk(&p, out) } else if p.extension().is_some_and(|x| x == "rs") { out.push(p) }
            }
        }
        let mut files = Vec::new();
        walk(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")), &mut files);
        assert!(files.len() > 50, "walked {} files — the tree is not where this test thinks", files.len());

        // Assembled at runtime so this test's own source does not contain
        // the needle it searches for — the first version caught itself.
        let needle = ["EXTRACT(", "EPOCH"].concat();
        let mut bad = Vec::new();
        for f in files {
            let src = std::fs::read_to_string(&f).unwrap();
            let lines: Vec<&str> = src.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if !code.contains(&needle) { continue; }
                // The cast may close a parenthesised expression on the next
                // line; two lines is the window a reader would check.
                let window = lines[n..(n + 2).min(lines.len())].join(" ");
                let cast = ["::float8", "::bigint", "::int8", "::double precision", "::int4", "::integer"]
                    .iter().any(|c| window.contains(c));
                if !cast {
                    bad.push(format!("{}:{}", f.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap().display(), n + 1));
                }
            }
        }
        assert!(bad.is_empty(), "{needle} …) without an explicit cast — NUMERIC will not decode into f64/i64: {bad:?}");
    }

    use super::*;

    /// Boot deletes a retired key's row only at a value that does not open
    /// it; an OPEN retired bridge stays for the boot refusal to name, and a
    /// live gate is never touched.
    /// Second review: `bridge_standing` reads the v1-token bridge exactly as
    /// the gateway does — a value the gateway treats as closed is no
    /// standing bridge, and an opening one is.
    #[test]
    fn the_v1_bridge_standing_uses_the_gateways_truthiness() {
        for closed in ["0", "false", "no", "off", "closed"] {
            assert!(bridge_standing("NOO_CLUSTER_TOKEN_V1", closed, 90, false).is_none(), "{closed:?}");
        }
        for open in ["1", "open", "true", "yes", "on"] {
            assert!(bridge_standing("NOO_CLUSTER_TOKEN_V1", open, 90, false).is_some(), "{open:?}");
        }
    }

    #[test]
    fn only_a_retired_row_at_a_closed_value_is_cleared() {
        let row = |k: &str, v: &str| (k.to_string(), v.to_string());
        let rows = vec![
            row("NOO_NATS_LEGACY_SHARED_CREDS", "0"),
            row("NOO_CLUSTER_LEGACY_FULL_ACCESS", "0"),
            row("NOO_BUS_PRINCIPAL", "required"),
            row("NOO_BUS_PRINCIPAL", "optional"),
            row("NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH", "1"),
            row("NOO_SELF_CALL_SHARED_SECRET", "0"),
            row("NOO_SELF_CALL_SHARED_SECRET", "1"),
            row("NOO_EXEC_APPROVAL_MODE", "approval"),
            row("NOO_APPROVAL_BREAK_GLASS", "0"),
            row("NOO_APPROVAL_BREAK_GLASS", "1"),
        ];
        assert_eq!(
            retired_rows_to_clear(&rows),
            vec![
                row("NOO_NATS_LEGACY_SHARED_CREDS", "0"),
                row("NOO_CLUSTER_LEGACY_FULL_ACCESS", "0"),
                row("NOO_BUS_PRINCIPAL", "required"),
                row("NOO_SELF_CALL_SHARED_SECRET", "0"),
                row("NOO_APPROVAL_BREAK_GLASS", "0"),
            ]
        );
        // The retired self-call bridge (see #371) held on is reported, never
        // silently deleted, and no other row is.
        assert_eq!(retired_inert_rows_held_open(&rows), vec![row("NOO_SELF_CALL_SHARED_SECRET", "1")]);
        assert!(retired_rows_to_clear(&[row("NOO_NATS_LEGACY_SHARED_CREDS", "1")]).is_empty(),
            "a retired key held open is left for verify's FAIL, never silently deleted");
        let src = include_str!("posture.rs");
        let apply = &src[src.find("pub async fn apply_security_posture").unwrap()..];
        assert!(apply[..apply.find("let mut applied").unwrap()].contains("clear_retired_rows(db, &pairs).await"),
            "boot no longer clears inert retired rows");
        assert!(apply[..apply.find("let mut applied").unwrap()].contains("retired_inert_rows_held_open(&pairs)"),
            "boot no longer reports an inert retired row held on");
    }
    use serde_json::json;

    #[test]
    fn clean_yaml_starts() {
        assert!(yaml_gate_refusal(&json!({})).is_none());
        // The rest of the `security:` section is still legitimate (the Python
        // worker's risk lists, the approval window) — only the gate is retired.
        assert!(yaml_gate_refusal(&json!({
            "security": {"exec_approval_timeout": 300, "high_risk_tools": ["shell"]}
        }))
        .is_none());
    }

    #[test]
    fn retired_gate_in_yaml_refuses_boot() {
        // The pre-fix shape: the shipped noomesh.yaml.example carried exactly
        // this, and it silently beat the (absent) posture row.
        let msg = yaml_gate_refusal(&json!({"security": {"exec_approval_mode": "auto"}}))
            .expect("a retired gate in yaml must refuse boot, not be ignored");
        assert!(msg.contains("security.exec_approval_mode"), "{msg}");
        assert!(msg.contains("noo security posture set NOO_EXEC_APPROVAL_MODE"), "{msg}");
    }

    #[test]
    fn a_null_key_is_not_a_setting() {
        // `security:\n  exec_approval_mode:` (commented out to nothing) is a
        // null, not an operator decision — do not brick a boot over it.
        assert!(yaml_gate_refusal(&json!({"security": {"exec_approval_mode": null}})).is_none());
    }

    /// the classification must actually split the list. A catalog that
    /// somehow had no bridges would make `apply-profile` identical to the old
    /// behaviour while every test below still passed.
    #[test]
    fn the_catalog_has_both_kinds() {
        assert!(gate_keys().count() > 0, "no gate keys");
        assert!(bridge_keys().count() > 0, "no bridge keys — nothing is protected");
        assert_eq!(
            gate_keys().count() + bridge_keys().count(),
            POSTURE_CATALOG.len(),
            "a key is neither gate nor bridge"
        );
    }

    /// The key R43 was actually about. Pinned by name: if someone reclassifies
    /// it as a Gate, `apply-profile hardened` starts closing the bus bridge
    /// again and a half-migrated fleet loses a node.
    #[test]
    fn the_known_bridges_are_bridges() {
        let key = "NOO_CLUSTER_TOKEN_V1";
        assert_eq!(
            kind_of(key).map(|k| k.is_bridge()),
            Some(true),
            "{key} must be a Bridge — a profile closing it breaks a rollout"
        );
        // ...and the gates are gates, or `hardened` stops hardening anything.
        for key in ["NOO_EXEC_APPROVAL_MODE", "NOO_MCP_EXTERNAL_ENABLED"] {
            assert_eq!(kind_of(key), Some(PostureKind::Gate), "{key} must be a Gate");
        }
    }

    /// Every bridge names the value that closes it, and it is not empty —
    /// `--include-bridges` writes that value, so a blank one would write an
    /// empty row and the gate accessor would read "unset".
    #[test]
    fn every_bridge_names_a_closing_value() {
        for k in bridge_keys() {
            match k.kind {
                PostureKind::Bridge { closed, .. } => {
                    assert!(!closed.trim().is_empty(), "{} has no closing value", k.key)
                }
                PostureKind::Gate => unreachable!("bridge_keys yielded a gate"),
            }
        }
    }

    #[test]
    fn every_key_has_an_operator_facing_reason() {
        for k in POSTURE_CATALOG {
            assert!(!k.why.trim().is_empty(), "{} has no `why`", k.key);
            // The CLI prints these on one line next to the key.
            assert!(k.why.len() <= 90, "{} `why` is too long to print: {}", k.key, k.why);
        }
    }

    #[test]
    fn no_duplicate_keys_in_the_catalog() {
        let mut seen = std::collections::BTreeSet::new();
        for k in POSTURE_CATALOG {
            assert!(seen.insert(k.key), "{} listed twice", k.key);
        }
    }

    #[test]
    fn every_retired_gate_is_a_posture_key() {
        // A retired key must have somewhere to GO. If it names a gate posture
        // will not accept, the error message sends the operator to a command
        // that fails.
        for (_, _, gate) in RETIRED_YAML_GATES {
            assert!(is_posture_key(gate), "{gate} is not a posture key");
        }
    }

    // ── Retired bridges ─────────────────────────────────────────────

    /// A retired bridge is not a posture key any more — nothing reads it, so
    /// `apply_security_posture` must not write it into the env as if it
    /// meant something — and it is not a bridge a profile can name.
    #[test]
    fn retired_bridges_are_out_of_the_catalog() {
        for b in RETIRED_BRIDGES {
            assert!(!is_posture_key(b.key), "{} is retired but still in POSTURE_CATALOG", b.key);
            assert!(!b.now.trim().is_empty() && !b.closed.trim().is_empty());
        }
        for key in [
            "NOO_CLUSTER_LEGACY_FULL_ACCESS",
            "NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH",
            "NOO_BUS_PRINCIPAL",
            "NOO_APPROVAL_BREAK_GLASS",
        ] {
            assert!(retired_bridge(key).is_some(), "{key} must be declared retired");
        }
    }

    /// The whole point: a row still holding a retired bridge OPEN refuses the
    /// boot, naming the key and the command that clears it.
    #[test]
    fn an_open_retired_bridge_refuses_boot() {
        for (k, v) in [
            ("NOO_CLUSTER_LEGACY_FULL_ACCESS", "1"),
            ("NOO_CLUSTER_LEGACY_FULL_ACCESS", "true"),
            ("NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH", "1"),
            ("NOO_BUS_PRINCIPAL", "optional"),
            ("NOO_BUS_PRINCIPAL", " Optional "),
            ("NOO_APPROVAL_BREAK_GLASS", "1"),
            ("NOO_APPROVAL_BREAK_GLASS", "true"),
            ("NOO_APPROVAL_BREAK_GLASS", "on"),
        ] {
            let msg = retired_bridge_refusal_for(&[(k, v, "noo_security_posture row")])
                .unwrap_or_else(|| panic!("{k}={v} must refuse boot"));
            assert!(msg.contains(k), "{msg}");
            assert!(msg.contains(&format!("noo security posture set {k} ")), "{msg}");
        }
    }

    /// A row at the value the old arm treated as CLOSED — or unset, or empty —
    /// is not an operator believing in a bridge. Refusing it would brick every
    /// install that did the right thing and closed the bridge.
    #[test]
    fn a_closed_or_unset_retired_bridge_does_not_refuse() {
        for (k, v) in [
            ("NOO_CLUSTER_LEGACY_FULL_ACCESS", "0"),
            ("NOO_CLUSTER_LEGACY_FULL_ACCESS", "false"),
            ("NOO_CLUSTER_LEGACY_FULL_ACCESS", ""),
            ("NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH", "0"),
            ("NOO_BUS_PRINCIPAL", "required"),
            ("NOO_BUS_PRINCIPAL", ""),
            ("NOO_SELF_CALL_SHARED_SECRET", "1"),
            ("NOO_APPROVAL_BREAK_GLASS", "0"),
            ("NOO_APPROVAL_BREAK_GLASS", ""),
            // Its arm compared the raw value: these were CLOSED there.
            ("NOO_APPROVAL_BREAK_GLASS", "Yes"),
            ("NOO_APPROVAL_BREAK_GLASS", " 1"),
        ] {
            assert!(retired_bridge_refusal_for(&[(k, v, "environment")]).is_none(), "{k}={v}");
        }
        assert!(retired_bridge_refusal_for(&[]).is_none());
    }

    /// The closing write must stay possible without SQL: the refusal tells
    /// the operator to run `posture set <key> <closed>`, so that route must
    /// accept exactly that write for a retired key (routes/users.rs).
    #[test]
    fn the_refusal_names_a_write_the_posture_route_accepts() {
        let src = include_str!("routes/users.rs");
        assert!(
            src.contains("crate::posture::retired_bridge(key)"),
            "posture_set must let a retired bridge be written to its closed value"
        );
        for b in RETIRED_BRIDGES {
            assert!(!retired_value_opens(b.key, b.closed), "{}: closed value reads as open", b.key);
        }
    }

    /// The approval break-glass gate, retired: open in the posture table or
    /// the environment, the gateway does not start and names the key and the
    /// closing write; closed, the row is cleared at boot and nothing refuses.
    /// It is out of the catalog, so no profile can set it and boot never
    /// writes it into the environment.
    #[test]
    fn the_retired_approval_break_glass_refuses_open_and_clears_closed() {
        let key = "NOO_APPROVAL_BREAK_GLASS";
        assert!(!is_posture_key(key), "{key} is retired but still in POSTURE_CATALOG");
        for src in ["noo_security_posture row", "environment"] {
            let msg = retired_bridge_refusal_for(&[(key, "1", src)])
                .expect("an open NOO_APPROVAL_BREAK_GLASS must refuse boot");
            assert!(msg.contains(key) && msg.contains(src), "{msg}");
            assert!(msg.contains("noo security posture set NOO_APPROVAL_BREAK_GLASS 0"), "{msg}");
            assert!(msg.contains("named operator"), "{msg}");
        }
        let row = |v: &str| (key.to_string(), v.to_string());
        assert_eq!(retired_rows_to_clear(&[row("0")]), vec![row("0")], "a closed row is cleared at boot");
        assert!(retired_rows_to_clear(&[row("1")]).is_empty(), "an open row is left for the refusal");
        assert!(retired_bridge_refusal_for(&[(key, "0", "noo_security_posture row")]).is_none());
    }
}

#[cfg(test)]
mod bridge_life_tests {
    use super::*;

    /// A bridge sitting at its closed value is not something the operator
    /// owes an account of. Reporting it would put a line in every boot log
    /// that is always there, which is how people learn to read past the line
    /// that matters.
    #[test]
    fn a_closed_bridge_has_no_standing() {
        assert!(bridge_standing("NOO_CLUSTER_TOKEN_V1", "0", 9999, false).is_none());
    }

    /// A retired bridge has no standing either: it is not in the catalog, so
    /// `report_open_bridges` never names it — the retired-bridge refusal does.
    #[test]
    fn a_retired_bridge_has_no_standing() {
        for b in RETIRED_BRIDGES {
            assert!(bridge_standing(b.key, "1", 9999, false).is_none(), "{}", b.key);
            assert!(bridge_standing(b.key, "optional", 9999, false).is_none(), "{}", b.key);
        }
    }

    #[test]
    fn a_gate_is_never_a_bridge_standing() {
        assert!(bridge_standing("NOO_EXEC_APPROVAL_MODE", "auto", 500, false).is_none());
        assert!(bridge_standing("NOO_MCP_EXTERNAL_ENABLED", "1", 500, false).is_none());
    }

    #[test]
    fn an_unknown_key_is_not_a_bridge() {
        assert!(bridge_standing("NOO_NOT_A_KEY", "1", 500, false).is_none());
    }

    #[test]
    fn overdue_is_measured_against_the_keys_own_window() {
        // NOO_CLUSTER_TOKEN_V1 declares 60 days.
        let b = bridge_standing("NOO_CLUSTER_TOKEN_V1", "1", 61, false).unwrap();
        assert_eq!(b.window_days, 60);
        assert!(b.is_overdue());
        assert_eq!(b.overdue_days(), 1);
        // A single global deadline shorter than the key's own would have
        // called this one late.
        let young = bridge_standing("NOO_CLUSTER_TOKEN_V1", "1", 31, false).unwrap();
        assert!(!young.is_overdue());
    }

    #[test]
    fn on_the_deadline_is_not_yet_overdue() {
        let b = bridge_standing("NOO_CLUSTER_TOKEN_V1", "1", 60, false).unwrap();
        assert!(!b.is_overdue(), "the window is 60 days, not 59");
    }

    /// Every bridge must declare a window, and it must be a real one. A zero
    /// would make the bridge overdue the moment it opened; a missing one
    /// cannot happen by construction, which is the point of putting it on the
    /// key rather than in a runbook.
    #[test]
    fn every_bridge_declares_a_usable_window() {
        for k in bridge_keys() {
            match k.kind {
                PostureKind::Bridge { window_days, .. } => assert!(
                    window_days > 0,
                    "{} declares a {}-day window",
                    k.key,
                    window_days
                ),
                PostureKind::Gate => unreachable!("bridge_keys yielded a gate"),
            }
        }
    }

    /// An age derived from `updated_at` is still an age, and must still be
    /// reportable — but it has to be MARKED, because the row could have been
    /// touched long after it opened. Silently presenting inference as
    /// evidence is the whole failure this work exists to stop.
    #[test]
    fn a_pre_migration_row_is_dated_but_says_so() {
        let b = bridge_standing("NOO_CLUSTER_TOKEN_V1", "1", 200, true).unwrap();
        assert!(b.dated_from_update);
        assert!(b.is_overdue());
    }
}
