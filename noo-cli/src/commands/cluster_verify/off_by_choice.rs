// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Grafana, Loki and Tempo off by choice (`cluster.monitoring: lean`).
//!
//! A one-machine install may leave the three out (`noo stack monitoring
//! off`). Their rows then say so and name the way back, instead of failing
//! for a container that is absent on purpose. The rule, and the whole of it:
//!
//! * What counts is the EFFECTIVE level, read by
//!   [`stack_monitoring::status_live`]: the install's noomesh.yaml through
//!   `declared_in` + `level_of`, then the shadows (COMPOSE_PROFILES listing
//!   `monitoring`, the controller profile), which force the set on. There is
//!   no second parser here.
//! * UNSET MEANS FULL. An install whose noomesh.yaml has no
//!   `cluster.monitoring` fails a dead Loki exactly as before: the fleet
//!   controller is itself a standalone install, and nothing else can tell
//!   it from a one-machine box.
//! * Off by choice is an OK row (shown under `-v`), not ACCEPTED: nothing
//!   is exposed or at risk, and on the install where it is the default an
//!   accepted row would print on every run.
//! * Only rows that need the RUNNING service change. The static rows (`loki
//!   listener`, `tempo listener`, `grafana sso`, the monitoring leaves) judge
//!   shipped files that govern the service the moment it is turned on, so a
//!   loosened config still fails while it is off. A data directory that
//!   HOLDS DATA (from before the switch) is still judged at rest; one that
//!   is absent, or empty (onboard creates every state directory, lean or
//!   not), has nothing in it to judge.
//!
//! [`stack_monitoring::status_live`]: crate::commands::stack_monitoring::status_live

use super::{ok, Check};
use crate::commands::stack_monitoring::{Level, Status};

/// The one sentence every off-by-choice row carries.
pub(crate) const DETAIL: &str = "not installed by choice (cluster.monitoring: lean): `noo stack monitoring on` turns it on";

/// Is the set off by choice on this install? The effective level only:
/// unset, a typo and a shadowed `lean` are all full here.
pub(crate) fn lean(monitoring: &Status) -> bool {
    monitoring.effective == Level::Lean
}

/// The row for a service that is not installed by choice.
pub(crate) fn row(name: &'static str) -> Check {
    ok(name, DETAIL)
}

/// `judge` as ever, unless the set is off by choice: then [`row`], and
/// `judge` (its gateway read, its docker inspect) is never run.
pub(crate) fn or_judge(name: &'static str, monitoring: &Status, judge: impl FnOnce() -> Check) -> Check {
    if lean(monitoring) {
        row(name)
    } else {
        judge()
    }
}

/// The `<name> at rest` rows of the three's data directories.
pub(crate) const STATE_ROWS: [&str; 3] = ["loki at rest", "tempo at rest", "grafana at rest"];

/// A state-dir row that has nothing to judge because the service is off by
/// choice: lean, the row is one of [`STATE_ROWS`], and the directory does
/// not exist or holds no data. Onboard creates every state directory, lean
/// or not, so a fresh lean install has three EMPTY ones: nothing in them is
/// in the clear (i1098). A directory that holds data from before the
/// switch (`off` keeps it) is judged at rest as ever: `None`. `holds_data`
/// is asked only for one of the three on lean, when the directory exists.
pub(crate) fn state_dir_row(name: &'static str, monitoring: &Status, exists: bool, holds_data: impl FnOnce() -> bool) -> Option<Check> {
    (lean(monitoring) && STATE_ROWS.contains(&name) && (!exists || !holds_data())).then(|| row(name))
}

/// Does the directory hold anything: an entry that is not a directory (a
/// file, a link, a socket), anywhere below it. Empty directories nested in
/// it are not data. An unreadable directory, or one nested deeper than
/// [`HOLDS_DATA_DEPTH`], counts as holding data: it cannot be shown empty,
/// so it is judged as before.
pub(crate) fn holds_data(dir: &std::path::Path) -> bool {
    holds_data_below(dir, HOLDS_DATA_DEPTH)
}

/// How deep [`holds_data`] looks for a file under empty directories.
const HOLDS_DATA_DEPTH: u32 = 8;

fn holds_data_below(dir: &std::path::Path, depth: u32) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else { return true };
    for entry in entries {
        let Ok(entry) = entry else { return true };
        // `file_type` does not follow a link: a link is an entry, data.
        let Ok(kind) = entry.file_type() else { return true };
        if !kind.is_dir() || depth == 0 || holds_data_below(&entry.path(), depth - 1) {
            return true;
        }
    }
    false
}

/// The gateway's refusal reason when the controller runs no Loki by choice.
pub(crate) const LOKI_OFF_REASON: &str = "loki_off";

/// The node's `log shipper` row when the controller's gateway refused its
/// batch because Loki is off by choice.
pub(crate) const SHIPPER_DETAIL: &str =
    "the controller keeps no node logs by choice (cluster.monitoring: lean, Loki not installed): `noo stack monitoring on` on the controller turns it on";

/// The gateway's refusal reason inside a shipper's `last_error`. The agent
/// writes `http <status> <reason>: <text>` (node-agent-go logship
/// `classify`); `None` for any other shape (a transport error, an older
/// gateway with no reason).
pub(crate) fn gateway_reason(last_error: &str) -> Option<&str> {
    let mut words = last_error.trim().strip_prefix("http ")?.split_whitespace();
    let status = words.next()?;
    if !status.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let reason = words.next()?;
    let reason = reason.strip_suffix(':').unwrap_or(reason);
    (!reason.is_empty() && !reason.contains(':')).then_some(reason)
}

#[cfg(test)]
mod tests {
    use super::super::warmup::{self, read_inspect, Inspected};
    use super::super::{logs_last_seen_check, log_shipper_check, parse_rfc3339_unix, tempo, Verdict};
    use super::*;
    use crate::commands::stack_monitoring::{declared_in, status_of, Facts};
    use serde_json::{json, Value};

    const LEAN: &str = "cluster:\n  image_retention: 2\n  monitoring: lean\n";
    const FULL: &str = "cluster:\n  image_retention: 2\n  monitoring: full\n";
    /// The fleet controller's own noomesh.yaml: no `cluster.monitoring`.
    const UNSET: &str = "cluster:\n  image_retention: 2\n";

    /// An install's effective level, from its noomesh.yaml text, the way
    /// `status_live` reads it (standalone profile, no COMPOSE_PROFILES).
    fn install(yaml: &str) -> Status {
        status_of(&Facts { declared: declared_in(yaml), compose_profiles: None, profile: "standalone".into() })
    }

    fn by_choice(c: &Check) -> bool {
        c.verdict == Verdict::Ok && c.detail == DETAIL && c.detail.contains("`noo stack monitoring on`")
    }

    // ── loki (and its warm-up wrapper) ───────────────────────────────

    fn loki_dead() -> Value {
        json!({ "loki_configured": true, "loki_url": "https://noo-loki:3100", "loki_ready": false })
    }
    const AT: &str = "2026-10-14T12:00:00Z";
    /// `docker inspect` of a Loki that started 30 s ago and never restarted.
    fn fresh_loki() -> Inspected {
        read_inspect(Ok((true, format!("true|{AT}||0|false|0"), String::new())))
    }
    fn now() -> i64 {
        parse_rfc3339_unix(AT).unwrap() + 30
    }
    fn loki(monitoring: &Status, inspected: Inspected) -> Check {
        warmup::loki_row_from(super::lean(monitoring), || (true, Some(loki_dead())), |_| inspected, now()).0
    }

    #[test]
    fn a_lean_install_says_loki_is_off_by_choice_and_never_asks() {
        let (c, seen) = warmup::loki_row_from(
            super::lean(&install(LEAN)),
            || panic!("lean must not read the gateway's /api/logs/status"),
            |_| panic!("lean must not docker inspect Loki"),
            now(),
        );
        assert!(by_choice(&c), "{c:?}");
        assert_eq!(c.name, "loki");
        assert!(seen.is_none());
    }

    #[test]
    fn a_full_install_fails_a_dead_loki_as_ever() {
        let gone = Inspected::Failed("Error: No such object: noo-loki".into());
        let c = loki(&install(FULL), gone);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("/ready did not answer"), "{}", c.detail);
    }

    /// THE RULE: no `cluster.monitoring` is full. The fleet controller is a
    /// standalone install with no such key; its dead Loki must stay red.
    #[test]
    fn unset_is_full_a_dead_loki_still_fails() {
        let st = install(UNSET);
        assert_eq!(st.declared, None);
        assert!(!super::lean(&st), "verify must read an unset cluster.monitoring as full");
        let gone = Inspected::Failed("Error: No such object: noo-loki".into());
        let c = loki(&st, gone);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        // A typo is full too, and a shadowed lean runs the set: judged.
        assert!(!super::lean(&install("cluster:\n  monitoring: off\n")));
        let shadowed = status_of(&Facts {
            declared: Some("lean".into()),
            compose_profiles: Some(("monitoring".into(), ".env".into())),
            profile: "standalone".into(),
        });
        assert!(!super::lean(&shadowed), "COMPOSE_PROFILES listing monitoring runs the set: judge it");
    }

    #[test]
    fn the_warm_up_wait_never_waits_on_a_lean_loki() {
        // Full: a Loki 30 s up is warm-up, and --wait waits on it.
        let full = install(FULL);
        let c = loki(&full, fresh_loki());
        assert_eq!(c.verdict, Verdict::Starting, "{}", c.detail);
        assert!(warmup::warmup_pending(super::lean(&full), || c.clone()));
        // Lean: nothing to wait for, and the row is not even probed.
        assert!(!warmup::warmup_pending(super::lean(&install(LEAN)), || panic!("lean must not probe Loki to decide the wait")));
        // Unset waits like full.
        let unset = install(UNSET);
        assert!(warmup::warmup_pending(super::lean(&unset), || loki(&unset, fresh_loki())));
    }

    // ── tempo ────────────────────────────────────────────────────────

    fn tempo_dead() -> Value {
        json!({ "exporting": true, "tempo_configured": true, "tempo_url": "https://tempo:3200", "tempo_ready": false })
    }

    #[test]
    fn the_tempo_row_is_off_by_choice_on_lean_and_fails_a_dead_tempo_otherwise() {
        let c = tempo::row_from(&install(LEAN), || panic!("lean must not read /api/traces/status"));
        assert!(by_choice(&c), "{c:?}");
        assert_eq!(c.name, tempo::ROW);
        for yaml in [FULL, UNSET] {
            let c = tempo::row_from(&install(yaml), || (Some(tempo_dead()), true));
            assert_eq!(c.verdict, Verdict::Fail, "{yaml}: {}", c.detail);
            assert!(c.detail.contains("/ready did not answer"), "{}", c.detail);
        }
    }

    // ── grafana door ─────────────────────────────────────────────────

    fn grafana_door(monitoring: &Status) -> Check {
        // As the run builds it: no Grafana, so no GRAFANA_ROOT_URL either.
        or_judge(crate::commands::grafana_door::ROW, monitoring, || {
            crate::commands::grafana_door::door_check(&crate::commands::grafana_door::Facts::default())
        })
    }

    #[test]
    fn the_grafana_door_is_off_by_choice_on_lean_and_fails_otherwise() {
        let c = grafana_door(&install(LEAN));
        assert!(by_choice(&c), "{c:?}");
        assert_eq!(c.name, "grafana door");
        for yaml in [FULL, UNSET] {
            assert_eq!(grafana_door(&install(yaml)).verdict, Verdict::Fail, "{yaml}");
        }
    }

    // ── state directories ────────────────────────────────────────────

    #[test]
    fn a_missing_state_dir_is_off_by_choice_on_lean_and_existing_data_is_still_judged() {
        let lean = install(LEAN);
        for name in STATE_ROWS {
            let c = state_dir_row(name, &lean, false, || panic!("{name}: an absent directory is never read"))
                .unwrap_or_else(|| panic!("{name}: absent on lean is by choice"));
            assert!(by_choice(&c), "{c:?}");
            assert_eq!(c.name, name);
            // Data from before the switch: judged at rest as ever.
            assert!(state_dir_row(name, &lean, true, || true).is_none(), "{name}: a directory with data must still be judged on lean");
        }
        // Not one of the three: never touched, never read.
        assert!(state_dir_row("postgres at rest", &lean, false, || panic!("not one of the three")).is_none());
        assert!(state_dir_row("postgres at rest", &lean, true, || panic!("not one of the three")).is_none());
        for yaml in [FULL, UNSET] {
            for name in STATE_ROWS {
                assert!(state_dir_row(name, &install(yaml), false, || panic!("full is never read")).is_none(), "{yaml} {name}");
                assert!(state_dir_row(name, &install(yaml), true, || false).is_none(), "{yaml} {name}: full judges even an empty one");
            }
        }
    }

    /// i1098: onboard creates every state directory, lean or not, so a fresh
    /// lean install has an EMPTY loki/tempo/grafana directory. Nothing in it
    /// is in the clear: by choice, not "plaintext on the root disk".
    #[test]
    fn an_empty_state_dir_on_lean_is_off_by_choice_and_a_non_empty_one_is_judged() {
        let lean = install(LEAN);
        let dir = std::env::temp_dir().join(format!("noo-state-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules/fake")).unwrap();
        assert!(!holds_data(&dir), "only empty subdirectories: no data");
        for name in STATE_ROWS {
            let c = state_dir_row(name, &lean, true, || holds_data(&dir)).unwrap_or_else(|| panic!("{name}: empty on lean is by choice"));
            assert!(by_choice(&c), "{c:?}");
        }
        std::fs::write(dir.join("rules/fake/index"), b"x").unwrap();
        assert!(holds_data(&dir), "a file two levels down is data");
        for name in STATE_ROWS {
            assert!(state_dir_row(name, &lean, true, || holds_data(&dir)).is_none(), "{name}: data is judged at rest");
        }
        let _ = std::fs::remove_dir_all(&dir);
        // A directory that cannot be read cannot be shown empty: data.
        assert!(holds_data(&dir), "an unreadable (here: missing) directory counts as holding data");
    }

    // ── logs: the node's shipper and the controller's last-seen ──────

    #[test]
    fn a_shipper_refused_with_loki_off_reads_as_off_by_choice() {
        let now = 1_800_000_000;
        let refused = |e: &str| json!({"enabled": true, "queued": 300, "shipped_total": 0, "last_accepted_unix": 0,
            "last_error": e, "route_ready": true, "spill_pending": false});
        let c = log_shipper_check("host3", &refused("http 503 loki_off: Loki is not installed on this controller (cluster.monitoring: lean)"), now, true);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.detail, SHIPPER_DETAIL);
        // A stall that ends on loki_off: the same.
        let mut stalled = refused("http 503 loki_off");
        stalled["last_accepted_unix"] = json!(now - 3600);
        assert_eq!(log_shipper_check("host3", &stalled, now, true).detail, SHIPPER_DETAIL);
        // Loki down on a full controller: the refusal fails as ever.
        let c = log_shipper_check("host3", &refused("http 503 loki_down: Loki unreachable"), now, true);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
    }

    /// i1098: on a `loki_off` refusal the agent PAUSES itself (`enabled:
    /// false`, `reason: loki_off`; node-agent-go logship). That is the
    /// by-choice state on every fresh lean install: OK, no remedy, never
    /// "hand-edit /etc/noo-node-agent.env".
    #[test]
    fn a_shipper_paused_on_loki_off_reads_as_off_by_choice() {
        let now = 1_800_000_000;
        let paused = json!({"enabled": false, "reason": "loki_off", "queued": 0, "shipped_total": 0, "dropped_total": 1,
            "last_accepted_unix": 0, "route_ready": true, "spill_pending": false,
            "last_error": "http 410 loki_off: log search is off on this controller by choice (noo stack monitoring on)"});
        let c = log_shipper_check("host3", &paused, now, true);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert_eq!(c.detail, SHIPPER_DETAIL);
        assert!(c.remedy.is_none());
        // The agent's own `reason` field alone says the same.
        let mut reason_only = paused.clone();
        reason_only["last_error"] = json!("");
        assert_eq!(log_shipper_check("host3", &reason_only, now, true).detail, SHIPPER_DETAIL);
        // Off for any other reason still warns with the env remedy.
        let off = json!({"enabled": false, "last_error": "NOO_LOG_SHIP=0"});
        let c = log_shipper_check("host3", &off, now, true);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.remedy.unwrap_or_default().contains("NOO_LOG_SHIP=1"));
    }

    #[test]
    fn the_gateway_reason_is_read_from_the_agents_last_error() {
        assert_eq!(gateway_reason("http 503 loki_off: Loki is off"), Some("loki_off"));
        assert_eq!(gateway_reason("http 503 loki_off"), Some("loki_off"));
        assert_eq!(gateway_reason("http 503: Loki is off"), None, "an older gateway names no reason");
        assert_eq!(gateway_reason("transport: dial tcp: loki_off"), None);
        assert_eq!(gateway_reason("http abc loki_off"), None);
    }

    #[test]
    fn logs_last_seen_is_off_by_choice_on_lean_and_fails_a_stale_node_otherwise() {
        let now = 1_800_000_000;
        let text = format!("noo_logs_last_seen_unix{{node=\"host3\"}} {}\n", now - 3600);
        let roster = vec![("host3".to_string(), true)];
        let row = |st: &Status| or_judge("logs last seen", st, || logs_last_seen_check(Some(&text), &roster, now));
        assert!(by_choice(&row(&install(LEAN))));
        assert_eq!(row(&install(FULL)).verdict, Verdict::Fail);
        assert_eq!(row(&install(UNSET)).verdict, Verdict::Fail);
    }
}
