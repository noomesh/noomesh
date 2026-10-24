// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Is anything actually listening to the host command spool?
//!
//! The gateway has zero Docker access, so every host-side action it takes is a
//! request written into a spool directory. Until now it had no way to know
//! whether a daemon was reading that directory — it wrote the file, saw the
//! write succeed, and told the operator the work was queued.
//!
//! That is not the same claim, and on 2026-08-06 the difference mattered. The
//! host watcher had been running since 2026-08-01. `db-resync` was added to
//! its script on the 4th. Nothing restarted the service, so the running
//! process had never heard of the op. For two days the dependency watchdog
//! queued repairs and alerted "🔧 Queued `noo security secrets resync --all`
//! on the host watcher", and every one of those commands was rejected as
//! "invalid op" by a process reading a two-day-old copy of the script.
//!
//! The failure was not the stale script — that is ordinary operational drift.
//! The failure was that the gateway ASSERTED something it had not checked.
//! An honest "I cannot repair this myself, run X by hand" would have been
//! acted on the same day.
//!
//! Both host daemons publish `hostd.heartbeat.json` into the spool:
//! `noo-hostd` (node-agent-go/internal/hostd) and, during the migration, the
//! bash watcher. The op list in it is the one the RUNNING PROCESS has, which
//! is the only version that can answer this question.

use serde::Deserialize;

/// Heartbeat schema — mirrors `hostd.Heartbeat` in Go (and the `jq -n`
/// object the retired bash watcher wrote). Unknown fields are ignored so a newer
/// daemon can add one without breaking an older gateway.
#[derive(Debug, Deserialize)]
pub struct Heartbeat {
    #[serde(default)]
    pub pid: i64,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub interval_secs: i64,
    #[serde(default)]
    pub ops: Vec<String>,
}

/// What we know about the host daemon, with respect to one specific op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    /// A live daemon that implements the op. Only this variant justifies
    /// telling an operator a repair is under way.
    Ready { version: String },
    /// Alive, but this binary does not implement the op — the exact
    /// stale-deployment case above.
    OpUnsupported { version: String },
    /// A heartbeat exists but has not been refreshed. The daemon died, or was
    /// never restarted after the spool moved.
    Stale { last: String },
    /// No heartbeat at all. Either nothing is installed, or something very old
    /// is running that predates heartbeats entirely.
    Absent,
    /// The heartbeat is there and unreadable. Deliberately distinct from
    /// `Absent`: "I could not tell" is not "nothing is running", and
    /// collapsing them would license the same overconfident claim in reverse.
    Unknown { reason: String },
}

impl DaemonStatus {
    /// Whether the caller may promise this op will actually run.
    pub fn will_run(&self) -> bool {
        matches!(self, DaemonStatus::Ready { .. })
    }

    /// Operator-facing explanation of why it will not, and what to do. Empty
    /// for `Ready`.
    pub fn remediation(&self, op: &str) -> String {
        match self {
            DaemonStatus::Ready { .. } => String::new(),
            DaemonStatus::OpUnsupported { version } => format!(
                "the host daemon is running ({version}) but does not implement `{op}` — \
                 it is out of date relative to this gateway. Update it and restart: \
                 `noo onboard --only services` (or `noo-hostd install`). If the retired \
                 bash watcher is still running here, stop it: \
                 `systemctl --user disable --now noo-host-watcher`."
            ),
            DaemonStatus::Stale { last } => format!(
                "the host daemon last checked in at {last} and has stopped — nothing is \
                 reading the spool, so `{op}` would never run. Start it: \
                 `systemctl --user start noo-hostd` (or `noo-hostd install` if it was \
                 never installed)."
            ),
            DaemonStatus::Absent => format!(
                "no host daemon is running — nothing reads the command spool, so `{op}` \
                 would never run. Install it with `noo-hostd install` on the controller."
            ),
            DaemonStatus::Unknown { reason } => format!(
                "could not determine whether a host daemon is running ({reason}), so \
                 `{op}` cannot be relied on."
            ),
        }
    }
}

fn spool_dir() -> String {
    std::env::var("NOO_HOST_SPOOL_DIR").unwrap_or_else(|_| "/var/run/noo-spool".into())
}

/// Read the heartbeat and classify it against `op`.
///
/// This is a single small file read with no database, no network and no lock —
/// which is what makes it safe to call from the alert path. The dependency
/// watchdog's whole reason for existing is that Postgres is down; a liveness
/// check that touched the database would be dead exactly when it is needed.
pub async fn probe(op: &str) -> DaemonStatus {
    let path = std::path::Path::new(&spool_dir()).join("hostd.heartbeat.json");
    let raw = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return DaemonStatus::Absent,
        Err(e) => {
            return DaemonStatus::Unknown {
                reason: format!("cannot read {}: {e}", path.display()),
            }
        }
    };
    let hb: Heartbeat = match serde_json::from_slice(&raw) {
        Ok(h) => h,
        Err(e) => {
            return DaemonStatus::Unknown {
                reason: format!("heartbeat is not valid JSON: {e}"),
            }
        }
    };
    classify(&hb, op, chrono::Utc::now())
}

/// Pure classification, split out so the staleness and support rules are
/// testable without a filesystem.
pub fn classify(hb: &Heartbeat, op: &str, now: chrono::DateTime<chrono::Utc>) -> DaemonStatus {
    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&hb.ts) else {
        // An unparseable timestamp fails CLOSED. We cannot date the evidence,
        // so we do not get to rely on it.
        return DaemonStatus::Unknown {
            reason: format!("unparseable heartbeat timestamp {:?}", hb.ts),
        };
    };
    // Three intervals, matching hostd.Heartbeat.Stale in Go. One would flag
    // ordinary scheduling jitter as death and produce false "host daemon down"
    // text in the middle of a repair that is working.
    let interval = if hb.interval_secs > 0 { hb.interval_secs } else { 15 };
    if (now - ts.with_timezone(&chrono::Utc)).num_seconds() > 3 * interval {
        return DaemonStatus::Stale { last: hb.ts.clone() };
    }
    if !hb.ops.iter().any(|o| o == op) {
        return DaemonStatus::OpUnsupported { version: hb.version.clone() };
    }
    DaemonStatus::Ready { version: hb.version.clone() }
}

/// The newest Postgres dump hostd saw in the backup directory
/// (`backup.newest_ts` in its heartbeat). A second witness for "when was the
/// last backup": it comes from the FILES, through a daemon that survives a
/// dead database, so it still answers when the scheduler's own history cannot.
/// `None` when there is no heartbeat, no such field (an older daemon), or no dump.
pub fn newest_backup_from(raw: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    #[derive(Deserialize)]
    struct Beat {
        backup: Option<Facts>,
    }
    #[derive(Deserialize)]
    struct Facts {
        #[serde(default)]
        newest_ts: String,
    }
    let beat: Beat = serde_json::from_slice(raw).ok()?;
    let ts = beat.backup?.newest_ts;
    chrono::DateTime::parse_from_rfc3339(&ts).ok().map(|t| t.with_timezone(&chrono::Utc))
}

/// [`newest_backup_from`] over the spool's heartbeat file.
pub async fn newest_backup() -> Option<chrono::DateTime<chrono::Utc>> {
    let path = std::path::Path::new(&spool_dir()).join("hostd.heartbeat.json");
    newest_backup_from(&tokio::fs::read(&path).await.ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb(ts: &str, ops: &[&str]) -> Heartbeat {
        Heartbeat {
            pid: 1,
            version: "test".into(),
            ts: ts.into(),
            interval_secs: 15,
            ops: ops.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    /// The 2026-08-06 case, as a test: a perfectly healthy daemon that simply
    /// predates the op. It must NOT read as ready.
    #[test]
    fn a_live_daemon_missing_the_op_is_not_ready() {
        let fresh = now().to_rfc3339();
        let s = classify(&hb(&fresh, &["recreate", "restart", "backup"]), "db-resync", now());
        assert!(!s.will_run(), "a daemon without the op reported ready: {s:?}");
        assert!(
            s.remediation("db-resync").contains("does not implement"),
            "remediation must name the actual problem, got: {}",
            s.remediation("db-resync")
        );
    }

    #[test]
    fn a_live_daemon_with_the_op_is_ready() {
        let fresh = now().to_rfc3339();
        assert!(classify(&hb(&fresh, &["db-resync"]), "db-resync", now()).will_run());
    }

    #[test]
    fn a_daemon_that_stopped_reads_as_stale_not_ready() {
        let old = (now() - chrono::Duration::minutes(10)).to_rfc3339();
        let s = classify(&hb(&old, &["db-resync"]), "db-resync", now());
        assert!(matches!(s, DaemonStatus::Stale { .. }), "got {s:?}");
        assert!(!s.will_run());
    }

    /// Two intervals late is jitter, not death. Flagging it would put "the
    /// host daemon has stopped" into alerts during repairs that are working.
    #[test]
    fn ordinary_jitter_does_not_read_as_stale() {
        let recent = (now() - chrono::Duration::seconds(30)).to_rfc3339();
        assert!(classify(&hb(&recent, &["db-resync"]), "db-resync", now()).will_run());
    }

    /// The timestamp format is a contract across three languages: Go writes
    /// `time.Format("2006-01-02T15:04:05Z")`, bash writes
    /// `date -u +%Y-%m-%dT%H:%M:%SZ`, and this parses both. They agree today —
    /// pinning it here so a well-meaning change to either writer (adding
    /// fractional seconds, switching to `+00:00`) fails a test rather than
    /// turning every heartbeat into `Unknown` and disabling autoheal fleet-wide.
    #[test]
    fn the_exact_timestamp_both_daemons_emit_is_parseable() {
        for ts in ["2026-08-10T02:00:35Z", "2026-08-10T02:00:35+00:00"] {
            let hb = Heartbeat {
                pid: 1,
                version: "x".into(),
                ts: ts.into(),
                interval_secs: 15,
                ops: vec!["db-resync".into()],
            };
            // Fixed "now" one second later, so the assertion is about parsing
            // rather than about the clock.
            let now = chrono::DateTime::parse_from_rfc3339("2026-08-10T02:00:36Z")
                .unwrap()
                .with_timezone(&chrono::Utc);
            assert!(
                classify(&hb, "db-resync", now).will_run(),
                "heartbeat timestamp {ts:?} did not parse — the daemons emit this format"
            );
        }
    }

    /// "I could not tell" must never collapse into either confident answer.
    #[test]
    fn an_undateable_heartbeat_is_unknown_not_ready() {
        let s = classify(&hb("not-a-timestamp", &["db-resync"]), "db-resync", now());
        assert!(matches!(s, DaemonStatus::Unknown { .. }), "got {s:?}");
        assert!(!s.will_run());
    }

    /// Every non-ready status must tell the operator what to do. A status that
    /// only says "no" moves the guesswork rather than removing it.
    #[test]
    fn every_failure_status_carries_an_actionable_remedy() {
        for s in [
            DaemonStatus::OpUnsupported { version: "v1".into() },
            DaemonStatus::Stale { last: "2026-08-06T00:00:00Z".into() },
            DaemonStatus::Absent,
            DaemonStatus::Unknown { reason: "disk".into() },
        ] {
            let r = s.remediation("db-resync");
            assert!(!r.is_empty(), "{s:?} has no remediation text");
            assert!(r.contains("db-resync"), "{s:?} remediation does not name the op: {r}");
        }
        assert!(DaemonStatus::Ready { version: "v1".into() }.remediation("db-resync").is_empty());
    }

    #[test]
    fn the_newest_backup_is_read_from_the_heartbeat_and_absent_on_older_daemons() {
        let t = newest_backup_from(br#"{"pid":1,"backup":{"dir":"/b","newest_ts":"2026-10-23T07:31:00Z","count":2}}"#)
            .expect("a heartbeat carrying backup facts");
        assert_eq!(t.to_rfc3339(), "2026-10-23T07:31:00+00:00");
        assert!(newest_backup_from(br#"{"pid":1}"#).is_none());
        assert!(newest_backup_from(br#"{"pid":1,"backup":{"dir":"/b","count":0}}"#).is_none(), "no dump yet");
    }
}
