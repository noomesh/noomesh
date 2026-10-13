// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Dependency watchdog — pages a human when Postgres or NATS stops
//! answering, and tells them which failure it is.
//!
//! ## Why this exists
//!
//! `/health` returns 503 when the database or NATS is down (see
//! `routes::core::health`). That fixed the *reporting* gap — Docker now
//! marks the container unhealthy — but nothing consumes that signal in a
//! way that reaches a person, and nothing should: the compose healthcheck
//! only flips a status label, and the one automated consumer
//! (`noo-host-watcher.sh::check_health`) uses it to gate deploys, not to
//! watch a running system.
//!
//! So on 2026-08-03 the gateway ran for four hours with no database.
//! Every DB-backed subsystem failed — chat, service keys, heartbeat,
//! autonomy, ingest — and the outage was found by a human noticing that
//! answers had stopped, not by any alert. This loop closes that: an
//! outage that lasts longer than a deploy blip reaches the operator over
//! the same channel as every other alert.
//!
//! ## The invariant that makes this work
//!
//! **The alert path must not touch the failed dependency.** It doesn't,
//! and that is load-bearing rather than lucky:
//!
//! - `operator_alert::dispatch_raw` calls `send_channel_message` in
//!   process — no self-call, so no auth middleware and no
//!   `service_keys::resolve` on the alert path at all. (It used to POST to
//!   the `/api/channels/send` loopback with a cluster-HMAC bearer, which
//!   stayed DB-free only because the HMAC branch returns before that read.)
//! - `routes::communication::channels_send` binds its state as `_state`
//!   and calls `send_channel_message`, which reads env vars and makes one
//!   external HTTPS call. No Postgres, no NATS.
//! - The cooldown uses Redis but falls back to an in-process map.
//!
//! If a future change adds a DB write to that path — persisting channel
//! counters on send is the obvious candidate, since `noo_channel_stats`
//! already exists — this watchdog goes silent in exactly the situation it
//! was built for. Keep the send path dependency-free, or give this loop
//! its own transport.
//!
//! ## What it does NOT do
//!
//! It does not self-heal, deliberately. See `advice()`: the two failures
//! it distinguishes have opposite remedies, and only one of them is even
//! restart-shaped. Restarting Postgres on a credential mismatch would
//! have bounced every consumer in the fleet, on a 30-minute loop, for
//! four hours, and fixed nothing. Naming the remedy is worth more than
//! guessing at it.
//!
//! Redis is excluded on purpose, matching `/health`'s status-code scope:
//! it restarts on its own and the gateway keeps serving without it.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::state::AppState;

/// Probe cadence. Also the resolution of the "down for ~Ns" figure.
const INTERVAL_SECS: u64 = 30;
/// Don't probe until the gateway has finished coming up.
const STARTUP_GRACE_SECS: u64 = 60;
/// Consecutive failures before paging — 3 × 30s ≈ 90s. Long enough that a
/// Postgres restart during a deploy stays quiet, short enough that a real
/// outage is known about in under two minutes.
const FAIL_THRESHOLD: u32 = 3;
/// While a dependency stays down, re-page this often. The alert funnel's
/// (kind, target) cooldown does the suppressing.
const REPAGE_COOLDOWN_SECS: i64 = 1800;
/// Recovery notices are edge-triggered, so this only bites when a
/// dependency is flapping.
const RECOVERY_COOLDOWN_SECS: i64 = 300;

/// What the error says the operator should actually do. The distinction
/// matters more than the error text: these two look identical from the
/// outside ("the database is down") and have opposite remedies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remedy {
    /// The server is up and rejecting us. Restarting anything makes it worse.
    Credential,
    /// Nothing is listening. A restart is a plausible fix.
    Unreachable,
    /// Reachable, authenticated, not serving.
    Saturated,
    Unknown,
}

/// Per-dependency streak state.
#[derive(Default, Debug, PartialEq, Eq)]
struct DepState {
    consecutive_failures: u32,
    /// Whether we have paged for the current outage. Gates the recovery
    /// notice so a dependency that never went down doesn't announce that
    /// it came back.
    paged: bool,
    /// Whether a repair has already been queued for the CURRENT outage.
    /// Cleared on recovery, so the next outage gets its own single attempt.
    ///
    /// One attempt, not a retry loop. If the resync did not fix it, the cause
    /// is something resync cannot reach — a stale container environment, a
    /// second writer on the role — and re-queueing every 30 minutes would
    /// produce noise during an incident instead of help.
    repair_queued: bool,
}

#[derive(Default)]
struct WatchdogState {
    deps: HashMap<&'static str, DepState>,
}

/// The decision for one probe of one dependency. Split out from the IO so
/// the threshold/edge logic is testable without an `AppState`.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Below threshold, or steady-state healthy.
    None,
    /// Page the operator. `streak` is the consecutive-failure count.
    Page { streak: u32 },
    /// A dependency we previously paged about is answering again.
    Recovered,
}

fn next_action(entry: &mut DepState, ok: bool) -> Action {
    if ok {
        let was_paged = entry.paged;
        entry.consecutive_failures = 0;
        entry.paged = false;
        entry.repair_queued = false;
        return if was_paged { Action::Recovered } else { Action::None };
    }
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    if entry.consecutive_failures < FAIL_THRESHOLD {
        return Action::None;
    }
    entry.paged = true;
    Action::Page { streak: entry.consecutive_failures }
}

/// Whether to queue an automatic repair for this failure, latching so it
/// happens at most once per outage.
///
/// Deliberately narrow, and the narrowness is the safety argument:
///
/// - **Postgres only, `Credential` only.** This is the one failure with a
///   repair that is convergent rather than a guess. `Unreachable` gets a
///   restart suggestion in the alert and no action — restarting Postgres from
///   the gateway would bounce every consumer in the fleet to fix one
///   container's view.
/// - **Once per outage.** See [`DepState::repair_queued`].
/// - **The host side re-verifies.** `secrets resync` only ALTERs a role whose
///   stored password is rejected while a negative control is also rejected, so
///   a spurious trigger here is a no-op there rather than damage. Two
///   independent checks, and the one that acts is the one holding the
///   evidence.
fn should_queue_repair(entry: &mut DepState, dep: &str, remedy: Remedy) -> bool {
    if dep != "postgresql" || remedy != Remedy::Credential || entry.repair_queued {
        return false;
    }
    if !autoheal_enabled() {
        return false;
    }
    entry.repair_queued = true;
    true
}

/// `NOO_DB_AUTOHEAL=0` (or `false`/`off`) disables the automatic repair and
/// leaves the alert as the only output. On by default: the alert already tells
/// the operator to run exactly this command, and the gap between "we know the
/// fix" and "someone is awake to type it" is what made 2026-08-03 a four-hour
/// outage rather than a five-minute one.
fn autoheal_enabled() -> bool {
    !matches!(
        std::env::var("NOO_DB_AUTOHEAL").unwrap_or_default().as_str(),
        "0" | "false" | "off" | "no"
    )
}

/// Classify a Postgres failure from its SQLSTATE and message.
///
/// Pure so the real-world strings can be regression-tested; `code` is
/// `db_err.code()` when the error reached the server, `None` when it
/// didn't (connection-level failures carry no SQLSTATE).
fn classify_pg(code: Option<&str>, msg: &str) -> Remedy {
    // SQLSTATE class 28 is "invalid authorization specification"; 3D000 is
    // "database does not exist". Both mean the server answered and said no.
    if let Some(c) = code {
        return match c {
            "28P01" | "28000" | "3D000" => Remedy::Credential,
            _ => Remedy::Unknown,
        };
    }
    let m = msg.to_lowercase();
    if m.contains("password authentication failed")
        || (m.contains("role") && m.contains("does not exist"))
    {
        Remedy::Credential
    } else if m.contains("connection refused")
        || m.contains("no route to host")
        || m.contains("failed to lookup address")
        || m.contains("connection reset")
        || m.contains("broken pipe")
    {
        Remedy::Unreachable
    } else {
        Remedy::Unknown
    }
}

fn classify_pg_error(err: &sqlx::Error) -> Remedy {
    if matches!(err, sqlx::Error::PoolTimedOut) {
        return Remedy::Saturated;
    }
    let code = match err {
        sqlx::Error::Database(db) => db.code().map(|c| c.into_owned()),
        _ => None,
    };
    classify_pg(code.as_deref(), &err.to_string())
}

/// The operator-facing remedy line. This is the payload — the error string
/// alone doesn't tell you whether to restart something or not to.
fn advice(dep: &str, remedy: Remedy) -> &'static str {
    match (dep, remedy) {
        ("postgresql", Remedy::Credential) => {
            "Postgres is UP and rejecting the gateway — a restart will not fix this and \
             will bounce every other consumer. The role's password and the stored value \
             disagree, because the migration that sets the role password runs once and \
             hand-editing secrets/env.sops never reaches it.\n\
             Fix: `noo security secrets resync --all --dry-run` to confirm, then without \
             --dry-run to converge the role onto the store. Prefer that over `rotate`: the \
             store and every consumer already agree, so nothing needs a new secret or a \
             container recreate."
        }
        ("postgresql", Remedy::Unreachable) => {
            "Nothing is listening on the Postgres endpoint. Check the container \
             (`noo stack status`) and bring it back \
             (`noo stack restart --force postgres` — dist-aware, unlike raw compose). \
             A restart is a reasonable first move here."
        }
        ("postgresql", Remedy::Saturated) => {
            "Postgres is reachable and authenticating but not serving — the pool is timing \
             out. Look for long-running or idle-in-transaction sessions in pg_stat_activity \
             before restarting anything."
        }
        ("nats", _) => {
            "NATS is not answering, so every Python @worker_handler call is failing. Check \
             `noo stack status`. Note that after NATS comes back the gateway \
             recovers on its own, but a worker pool that connected without retry=True does \
             not — it holds a dead connection and returns \"no responders\" until \
             the gateway is restarted."
        }
        _ => "Check the gateway logs for the full error before acting.",
    }
}

async fn probe_postgres(state: &AppState) -> Result<(), (String, Remedy)> {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let remedy = classify_pg_error(&e);
            Err((e.to_string(), remedy))
        }
    }
}

async fn probe_nats(state: &AppState) -> Result<(), (String, Remedy)> {
    match state.nats.flush().await {
        Ok(()) => Ok(()),
        Err(e) => Err((e.to_string(), Remedy::Unreachable)),
    }
}

async fn evaluate(
    state: &AppState,
    wd: &Mutex<WatchdogState>,
    dep: &'static str,
    outcome: Result<(), (String, Remedy)>,
) {
    let (action, failure) = {
        let mut guard = wd.lock().await;
        let entry = guard.deps.entry(dep).or_default();
        match outcome {
            Ok(()) => (next_action(entry, true), None),
            Err(f) => (next_action(entry, false), Some(f)),
        }
    };

    if let Some((ref err, _)) = failure {
        tracing::warn!(dependency = dep, error = %err, "dependency_watchdog_probe_failed");
    }

    match action {
        Action::None => {}
        Action::Recovered => {
            tracing::info!(dependency = dep, "dependency_watchdog_recovered");
            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "dependency.recovered",
                    dep,
                    format!("✅ Gateway dependency `{dep}` is answering again."),
                )
                .investigate("noo health"),
                RECOVERY_COOLDOWN_SECS,
            )
            .await;
        }
        Action::Page { streak } => {
            let (err, remedy) = failure.expect("Page is only produced by a failed probe");
            let down_secs = streak as u64 * INTERVAL_SECS;
            tracing::error!(
                dependency = dep,
                streak,
                remedy = ?remedy,
                error = %err,
                "dependency_watchdog_down"
            );
            // The raw error is evidence for the log (it rides as the alert's
            // `detail`); the channel gets the class of failure and the advice.
            let message = format!(
                "🛑 Gateway dependency `{dep}` has been failing for ~{down_secs}s \
                 ({streak} consecutive probes).\n\n{}",
                advice(dep, remedy)
            );
            // Queue the repair BEFORE alerting, so the alert can say what was
            // done rather than the operator learning about it separately. The
            // spool write is a file rename — it does not depend on the
            // database that is down.
            let repair = {
                let mut guard = wd.lock().await;
                let entry = guard.deps.entry(dep).or_default();
                should_queue_repair(entry, dep, remedy)
            };
            let repair_note = if repair {
                // Verify a host daemon is alive AND implements this op before
                // writing the command. A successful spool write only proves
                // the file exists; it says nothing about whether anything will
                // read it. For two days in August 2026 this alert promised a
                // resync to a watcher that rejected every one as "invalid op"
                // — see crate::host_daemon for the full case.
                //
                // Probing FIRST, rather than writing and hedging the wording,
                // also keeps the spool clean: a command no daemon supports
                // would sit there unclaimed forever, indistinguishable from
                // one that is merely pending.
                let daemon = crate::host_daemon::probe("db-resync").await;
                if !daemon.will_run() {
                    tracing::error!(
                        status = ?daemon,
                        "dependency_watchdog_repair_skipped_no_host_daemon"
                    );
                    format!(
                        "\n\n⚠️ An automatic `noo security secrets resync --all` WAS NOT queued: \
                         {}\n\nRun it by hand on the controller: `noo security secrets resync --all`",
                        daemon.remediation("db-resync")
                    )
                } else {
                    match crate::routes::admin::host_spool_write_command(
                        "db-resync",
                        "noo-postgres",
                        &[],
                        "dependency_watchdog",
                    )
                    .await
                    {
                        Some(path) => {
                            tracing::warn!(spool_command = %path, "dependency_watchdog_repair_queued");
                            "\n\n🔧 Queued `noo security secrets resync --all` on the host daemon \
                             (once for this outage; the daemon was confirmed live and supporting \
                             this op before queueing). It converges the role onto the stored \
                             value, and re-verifies first — if nothing has actually drifted it is \
                             a no-op. If this alert does not clear within a few minutes, the \
                             cause is something resync cannot reach: most likely the gateway \
                             container is holding a stale environment and needs recreating, not \
                             restarting."
                                .to_string()
                        }
                        None => {
                            tracing::error!("dependency_watchdog_repair_spool_write_failed");
                            "\n\n⚠️ Tried to queue an automatic resync and could not write to the \
                             host spool — run `noo security secrets resync --all` by hand."
                                .to_string()
                        }
                    }
                }
            } else {
                String::new()
            };

            crate::operator_alert::send_operator_alert_with(
                state,
                crate::operator_alert::OperatorAlert::new(
                    "dependency.down",
                    dep,
                    format!("{message}{repair_note}"),
                )
                .detail(err.clone())
                .investigate("noo health"),
                REPAGE_COOLDOWN_SECS,
            )
            .await;
        }
    }
}

/// Spawn the watchdog. Registers with `loop_health` via `ManagedLoop`, so
/// the watchdog itself is watched.
pub fn spawn(state: Arc<AppState>) {
    let wd: Arc<Mutex<WatchdogState>> = Arc::new(Mutex::new(WatchdogState::default()));
    crate::managed_loop::ManagedLoop::new("dependency_watchdog", INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .spawn(state, move |state| {
            let wd = wd.clone();
            async move {
                let pg = probe_postgres(&state).await;
                evaluate(&state, &wd, "postgresql", pg).await;
                let nats = probe_nats(&state).await;
                evaluate(&state, &wd, "nats", nats).await;
                Ok(())
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that touch process env.
    ///
    /// Same bug as `mcp_external`, in a second module: `should_queue_repair`
    /// consults `NOO_DB_AUTOHEAL` through `autoheal_enabled()`, and two tests
    /// here set it to opposite values. Rust runs a binary's tests on parallel
    /// threads of ONE process, so whichever pair interleaves loses — and the
    /// test that FAILS is the one that never touched the variable, which is
    /// what makes this expensive to diagnose from a CI log.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Poison ignored on purpose: the lock guards an env var, not data, and a
    /// panicking sibling must not bury the original failure under a second.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn does_not_page_before_the_threshold() {
        let mut s = DepState::default();
        for _ in 1..FAIL_THRESHOLD {
            assert_eq!(next_action(&mut s, false), Action::None);
        }
        assert_eq!(
            next_action(&mut s, false),
            Action::Page { streak: FAIL_THRESHOLD }
        );
    }

    #[test]
    fn keeps_paging_while_down_so_the_funnel_owns_repeat_suppression() {
        let mut s = DepState::default();
        for _ in 0..FAIL_THRESHOLD {
            next_action(&mut s, false);
        }
        // Still reports Page; the (kind, target) cooldown in operator_alert
        // decides whether it actually goes out. Keeping it unconditional here
        // is what lets a failed delivery be retried on the next window.
        assert_eq!(
            next_action(&mut s, false),
            Action::Page { streak: FAIL_THRESHOLD + 1 }
        );
    }

    #[test]
    fn recovery_only_fires_if_we_actually_paged() {
        // A blip shorter than the threshold must not produce an all-clear for
        // an alarm nobody ever received.
        let mut s = DepState::default();
        next_action(&mut s, false);
        assert_eq!(next_action(&mut s, true), Action::None);
        assert_eq!(s, DepState::default());

        let mut s = DepState::default();
        for _ in 0..FAIL_THRESHOLD {
            next_action(&mut s, false);
        }
        assert_eq!(next_action(&mut s, true), Action::Recovered);
        // ...and only once.
        assert_eq!(next_action(&mut s, true), Action::None);
    }

    #[test]
    fn the_2026_08_03_outage_is_classified_as_a_credential_failure() {
        // The message sqlx surfaced during the four-hour outage. Restarting
        // Postgres would not have helped; this is the case where self-healing
        // by restart is actively wrong.
        let msg = "error returned from database: password authentication failed \
                   for user \"noo_app\"";
        assert_eq!(classify_pg(None, msg), Remedy::Credential);
        assert_eq!(classify_pg(Some("28P01"), msg), Remedy::Credential);
        assert!(advice("postgresql", Remedy::Credential).contains("will not fix this"));
    }

    #[test]
    fn a_missing_role_is_a_credential_failure_not_an_outage() {
        assert_eq!(
            classify_pg(None, "role \"noo_app\" does not exist"),
            Remedy::Credential
        );
        assert_eq!(classify_pg(Some("3D000"), "database ... does not exist"), Remedy::Credential);
    }

    #[test]
    fn a_dead_container_is_unreachable() {
        assert_eq!(
            classify_pg(None, "pool timed out; Connection refused (os error 111)"),
            Remedy::Unreachable
        );
        assert_eq!(
            classify_pg(None, "failed to lookup address information: Name or service not known"),
            Remedy::Unreachable
        );
        assert!(advice("postgresql", Remedy::Unreachable).contains("reasonable first move"));
    }

    #[test]
    fn an_unrecognised_sqlstate_does_not_claim_a_remedy() {
        // A server-side error we don't have a playbook for must not be
        // guessed at — a wrong remedy is worse than none.
        assert_eq!(classify_pg(Some("42P01"), "relation does not exist"), Remedy::Unknown);
        assert!(advice("postgresql", Remedy::Unknown).contains("before acting"));
    }

    #[test]
    fn nats_advice_covers_the_worker_pool_reconnect_trap() {
        assert!(advice("nats", Remedy::Unreachable).contains("no responders"));
    }

    // ── automatic repair gate ────────────────────────────────────────────
    //
    // These run in one process with the rest of the suite, and
    // `autoheal_enabled()` reads a process-wide env var — so the tests that
    // depend on the default must not race one that unsets it. Only
    // `autoheal_can_be_switched_off` touches NOO_DB_AUTOHEAL, and it restores
    // it; the others never set it.

    #[test]
    fn repair_is_queued_only_for_a_credential_failure_on_postgres() {
        let _guard = env_guard();
        for (dep, remedy, want) in [
            ("postgresql", Remedy::Credential, true),
            // Restarting Postgres from here would bounce every consumer in the
            // fleet to fix one container's view. Alert only.
            ("postgresql", Remedy::Unreachable, false),
            ("postgresql", Remedy::Saturated, false),
            ("postgresql", Remedy::Unknown, false),
            ("nats", Remedy::Unreachable, false),
            // A NATS credential verdict is not reachable today, but the gate
            // must key on the dependency too, not the remedy alone.
            ("nats", Remedy::Credential, false),
        ] {
            let mut s = DepState::default();
            assert_eq!(
                should_queue_repair(&mut s, dep, remedy),
                want,
                "{dep} / {remedy:?}"
            );
        }
    }

    #[test]
    fn repair_is_queued_at_most_once_per_outage() {
        let _guard = env_guard();
        let mut s = DepState::default();
        assert!(should_queue_repair(&mut s, "postgresql", Remedy::Credential));
        // Every subsequent tick of the SAME outage must not re-queue: a repair
        // that did not work will not work on the tenth attempt either, and
        // re-queueing turns an incident into a flood.
        for _ in 0..5 {
            assert!(!should_queue_repair(&mut s, "postgresql", Remedy::Credential));
        }
    }

    #[test]
    fn recovery_rearms_the_repair_for_the_next_outage() {
        let mut s = DepState::default();
        for _ in 0..FAIL_THRESHOLD {
            next_action(&mut s, false);
        }
        assert!(should_queue_repair(&mut s, "postgresql", Remedy::Credential));
        assert_eq!(next_action(&mut s, true), Action::Recovered);
        assert!(
            should_queue_repair(&mut s, "postgresql", Remedy::Credential),
            "a NEW outage must get its own attempt — the latch is per-outage, not per-process"
        );
    }

    #[test]
    fn autoheal_can_be_switched_off() {
        let _guard = env_guard();
        for off in ["0", "false", "off", "no"] {
            std::env::set_var("NOO_DB_AUTOHEAL", off);
            let mut s = DepState::default();
            assert!(
                !should_queue_repair(&mut s, "postgresql", Remedy::Credential),
                "NOO_DB_AUTOHEAL={off} must disable the repair"
            );
            assert!(
                !s.repair_queued,
                "a disabled autoheal must not consume the once-per-outage latch"
            );
        }
        std::env::set_var("NOO_DB_AUTOHEAL", "1");
        let mut s = DepState::default();
        assert!(should_queue_repair(&mut s, "postgresql", Remedy::Credential));
        std::env::remove_var("NOO_DB_AUTOHEAL");
    }
}

/// Enforcement for the invariant in this module's docs: **the alert path must
/// not touch the failed dependency.**
///
/// Documenting it is not enough. The path is DB-free today by construction,
/// but it is one plausible commit from breaking — persisting a counter on send
/// is a natural thing to add, and `noo_channel_stats` already exists to
/// receive it. The failure would be silent and would only show up during an
/// outage, which is the one moment nobody is reading gateway logs.
///
/// These read the source at compile time via `include_str!`, so they cost
/// nothing at runtime and cannot go stale against a moved file.
#[cfg(test)]
mod alert_path_is_dependency_free {
    const COMMUNICATION_RS: &str = include_str!("routes/communication.rs");
    const AUTH_RS: &str = include_str!("auth.rs");
    const OPERATOR_ALERT_RS: &str = include_str!("operator_alert.rs");

    /// Slice out one top-level `fn` body. Relies on rustfmt's guarantee that a
    /// top-level closing brace sits at column 0 — true throughout this crate,
    /// and a far smaller assumption than brace-matching through string
    /// literals and comments.
    fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
        let needle = format!("fn {name}(");
        let start = src
            .find(&needle)
            .unwrap_or_else(|| panic!("no `{needle}` — was it renamed? update this test"));
        let rest = &src[start..];
        let end = rest
            .find("\n}\n")
            .unwrap_or_else(|| panic!("no top-level close for `{needle}`"));
        &rest[..end]
    }

    fn assert_no_db(what: &str, body: &str) {
        for marker in ["state.db", "sqlx::", "&self.db", "fetch_one", "fetch_all"] {
            assert!(
                !body.contains(marker),
                "`{what}` now references `{marker}`.\n\n\
                 This is the operator-alert delivery path. If it touches Postgres, \
                 the dependency watchdog goes silent in exactly the outage it exists \
                 to report — the 2026-08-03 four-hour blackout with no alert.\n\n\
                 If the DB access is genuinely needed here, give the watchdog its own \
                 transport first; do not just delete this assertion. \
                 See dependency_watchdog.rs module docs."
            );
        }
    }

    #[test]
    fn channels_send_handler_stays_db_free() {
        assert_no_db(
            "channels_send",
            fn_body(COMMUNICATION_RS, "channels_send"),
        );
    }

    #[test]
    fn send_channel_message_stays_db_free() {
        assert_no_db(
            "send_channel_message",
            fn_body(COMMUNICATION_RS, "send_channel_message"),
        );
    }

    #[test]
    fn dispatch_raw_stays_db_free() {
        assert_no_db("dispatch_raw", fn_body(OPERATOR_ALERT_RS, "dispatch_raw"));
    }

    #[test]
    fn cluster_hmac_is_checked_before_the_middlewares_only_db_read() {
        // `service_keys::resolve` hits Postgres. The cluster-token branch must
        // return before it, or authenticating the loopback alert POST would
        // itself require the database that is down.
        //
        // Scoped to the function body on purpose: `service_keys::resolve` is
        // also named in the doc comment above it, and a whole-file search
        // matches that first and compares two unrelated positions.
        let body = fn_body(AUTH_RS, "require_any_auth");
        let hmac = body
            .find("if verify_cluster_token(&t)")
            .expect("cluster-token branch not found — was require_any_auth restructured?");
        let db_read = body
            .find("service_keys::resolve(&state.db")
            .expect("the service-key DB lookup is gone — has this invariant moved?");
        assert!(
            hmac < db_read,
            "the service-key DB lookup now runs before (or instead of) the \
             cluster-HMAC check. Operator alerts authenticate with the cluster \
             token, so this ordering is what lets an alert go out while Postgres \
             is down. See dependency_watchdog.rs module docs."
        );
    }
}
