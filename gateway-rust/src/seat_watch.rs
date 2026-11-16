// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Seat watch — is each kiosk seat's display running, and is the seat
//! still reporting?
//!
//! ## Why this exists
//!
//! A seat posts its state every 60 s (`seat_heartbeat`, routes/seats.rs):
//! `kiosk_display` is `systemctl is-active kiosk.service`. The gateway
//! stored that JSON and never read it; only `noo cluster verify` judged it,
//! CLI-side. On 2026-11-16 a seat's display sat at `activating` from
//! 19:27Z and nothing told the operator: there was no alert kind for a
//! seat at all, and none for a seat that stops reporting either.
//!
//! This loop raises two persisting conditions through the operator-alert
//! funnel, so the funnel's own schedule owns timing: one message at onset,
//! its standard reminders, and one "fine again" line on recovery.
//!
//! - `seat_display_down`: the heartbeat is fresh and the display has not
//!   been `active` for [`DEBOUNCE_SECS`]. A bundle apply, the watchdog and
//!   a reboot all pass through `activating` for seconds; those never page.
//!   The predicate is verify's own (`seat_checks`, the `display` row), so
//!   the alert and the row cannot disagree.
//! - `seat_silent`: no heartbeat for [`SILENT_SECS`]. While a seat is
//!   silent its display state is unknown: an open `seat_display_down`
//!   stays open, neither cleared nor raised.
//!
//! The debounce clock is in process. A gateway restart forgets it, but an
//! already-announced condition is remembered by the funnel (Redis): a seat
//! whose `seat_display_down` is open skips the debounce, and the funnel's
//! schedule answers Quiet, so the onset is never sent twice.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;

use crate::operator_alert::OperatorAlert;
use crate::state::AppState;

/// How often to look. One query over a handful of rows.
const INTERVAL_SECS: u64 = 60;
const STARTUP_GRACE_SECS: u64 = 90;
/// A display down this long pages. Longer than any restart a roll, a
/// bundle apply or the kiosk watchdog makes.
pub const DEBOUNCE_SECS: i64 = 300;
/// A heartbeat older than this is not used to judge the display (verify's
/// `SEAT_HEARTBEAT_MAX_AGE_SECS`: the seat posts every 60 s).
pub const FRESH_SECS: i64 = 180;
/// No heartbeat for this long pages. Longer than verify's 180 s so a
/// reboot rides through.
pub const SILENT_SECS: i64 = 600;

pub const KIND_DISPLAY: &str = "seat_display_down";
pub const KIND_SILENT: &str = "seat_silent";

/// What one seat's row says right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// Display active (or the seat runs no kiosk); reporting.
    Fine,
    /// The seat runs no kiosk: nothing to watch on the display.
    NoKiosk,
    /// Revoked: nothing to watch at all.
    Gone,
    /// Fresh heartbeat, display not active: kiosk.service's state.
    DisplayDown(String),
    /// Heartbeat older than [`FRESH_SECS`], younger than [`SILENT_SECS`]:
    /// judge nothing.
    Stale,
    /// No heartbeat for this many seconds (≥ [`SILENT_SECS`]).
    Silent(i64),
    /// Enrolled, never heard from: the enrolment is operator-attended and
    /// verify says it; no alert.
    Unheard,
}

/// The seat's condition, from its row. Same display predicate as verify:
/// kiosk binaries present (not `absent`) and kiosk.service stated and not
/// `active`.
pub fn seat_condition(hb: Option<&Value>, last_seen: Option<i64>, revoked: bool, now: i64) -> Seen {
    if revoked {
        return Seen::Gone;
    }
    let Some(seen) = last_seen else { return Seen::Unheard };
    let age = (now - seen).max(0);
    if age >= SILENT_SECS {
        return Seen::Silent(age);
    }
    if age > FRESH_SECS {
        return Seen::Stale;
    }
    let hb = hb.unwrap_or(&Value::Null);
    let bins = hb["kiosk_bins"].as_str();
    let unit = hb["kiosk_display"].as_str().unwrap_or("");
    if !bins.is_some_and(|b| b != "absent") || unit.is_empty() {
        return Seen::NoKiosk;
    }
    if unit != "active" {
        return Seen::DisplayDown(unit.to_string());
    }
    Seen::Fine
}

/// What to do about one kind for one seat this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    /// Hand the condition to the funnel (its schedule decides whether a
    /// message leaves).
    Raise,
    /// The condition is over: close it (a message only if it was announced).
    Clear,
    /// Down, but not for [`DEBOUNCE_SECS`] yet.
    Wait,
    /// Unknown: leave an open condition open.
    Leave,
}

/// The display decision. `first_bad` is when this process first saw the
/// display down (the debounce clock); `open` is whether the funnel holds an
/// announced condition for this seat (survives a restart).
pub fn display_act(seen: &Seen, first_bad: Option<i64>, open: bool, now: i64) -> Act {
    match seen {
        Seen::DisplayDown(_) => {
            if open || now - first_bad.unwrap_or(now) >= DEBOUNCE_SECS {
                Act::Raise
            } else {
                Act::Wait
            }
        }
        Seen::Stale | Seen::Silent(_) | Seen::Unheard => Act::Leave,
        Seen::Fine | Seen::NoKiosk | Seen::Gone => Act::Clear,
    }
}

/// The reporting decision.
pub fn silent_act(seen: &Seen) -> Act {
    match seen {
        Seen::Silent(_) => Act::Raise,
        Seen::Unheard => Act::Leave,
        _ => Act::Clear,
    }
}

/// The debounce clock after this tick: kept while down, unchanged while
/// unknown, dropped once the display is judged fine.
pub fn next_first_bad(seen: &Seen, prev: Option<i64>, now: i64) -> Option<i64> {
    match seen {
        Seen::DisplayDown(_) => Some(prev.unwrap_or(now)),
        Seen::Stale | Seen::Silent(_) | Seen::Unheard => prev,
        Seen::Fine | Seen::NoKiosk | Seen::Gone => None,
    }
}

/// The channel's Next line for a seat: verify, whose seat rows print the
/// exact root repair (`sudo ~<user>/.local/libexec/noo-seat/noo kiosk
/// seat-sync --migrate`, `systemctl status noo-seat-sync.timer`). Those
/// commands cannot be the Next line themselves: the channel scrubber masks
/// every `noo-<name>` shape (a container name) and `noo-seat` is one, so the
/// command would arrive as `…/[internal]/noo`. Verify's output is the
/// operator's own terminal, unscrubbed.
pub fn next_for(seat: &str) -> String {
    format!("noo cluster verify {seat}")
}

pub fn display_alert(seat: &str, unit: &str, detail: String) -> OperatorAlert {
    OperatorAlert::new(
        KIND_DISPLAY,
        seat,
        format!(
            "Seat '{seat}': the kiosk display is not running (state: {unit}). \
             The repair is `kiosk seat-sync --migrate`, run as root on the seat; verify prints the exact command."
        ),
    )
    .detail(detail)
    .investigate(next_for(seat))
    .persisting()
}

pub fn display_recovered(seat: &str) -> OperatorAlert {
    OperatorAlert::new(KIND_DISPLAY, seat, format!("Seat '{seat}': the kiosk display is running again."))
        .investigate(next_for(seat))
}

pub fn silent_alert(seat: &str, age: i64) -> OperatorAlert {
    OperatorAlert::new(
        KIND_SILENT,
        seat,
        format!(
            "Seat '{seat}' has not reported to the controller for {}: the seat is off, offline, or its sync timer stopped.",
            crate::egress::human_duration(age)
        ),
    )
    .detail(format!("last heartbeat {age}s ago"))
    .investigate(next_for(seat))
    .persisting()
}

pub fn silent_recovered(seat: &str) -> OperatorAlert {
    OperatorAlert::new(KIND_SILENT, seat, format!("Seat '{seat}' is reporting to the controller again."))
        .investigate(next_for(seat))
}

fn first_bad_map() -> &'static Mutex<HashMap<String, i64>> {
    static MAP: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One pass over every seat (revoked ones too, so their conditions close).
pub async fn tick(state: &Arc<AppState>) {
    let rows = match crate::repo::seats::watch_rows(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "seat_watch_query_failed");
            return;
        }
    };
    let now = chrono::Utc::now().timestamp();
    for (seat, last_seen, hb, revoked) in rows {
        let seen = seat_condition(hb.as_ref(), last_seen.map(|t| t.timestamp()), revoked, now);
        let prev = first_bad_map().lock().ok().and_then(|m| m.get(&seat).copied());
        let open = matches!(seen, Seen::DisplayDown(_))
            && crate::operator_alert::condition_open(state, KIND_DISPLAY, &seat).await;
        match display_act(&seen, prev, open, now) {
            Act::Raise => {
                let unit = match &seen {
                    Seen::DisplayDown(u) => u.as_str(),
                    _ => "",
                };
                let h = hb.as_ref().unwrap_or(&Value::Null);
                let detail = format!(
                    "kiosk.service={unit} kiosk-serve={} quality={} console={}",
                    h["kiosk_serve"].as_str().unwrap_or("?"),
                    h["kiosk"]["quality"].as_str().unwrap_or("?"),
                    h["console_build"].as_str().unwrap_or("?"),
                );
                crate::operator_alert::send_operator_alert_with(state, display_alert(&seat, unit, detail), 0).await;
            }
            Act::Clear => {
                crate::operator_alert::clear_operator_alert(state, display_recovered(&seat)).await;
            }
            Act::Wait | Act::Leave => {}
        }
        match silent_act(&seen) {
            Act::Raise => {
                if let Seen::Silent(age) = seen {
                    crate::operator_alert::send_operator_alert_with(state, silent_alert(&seat, age), 0).await;
                }
            }
            Act::Clear => {
                crate::operator_alert::clear_operator_alert(state, silent_recovered(&seat)).await;
            }
            Act::Wait | Act::Leave => {}
        }
        if let Ok(mut m) = first_bad_map().lock() {
            match next_first_bad(&seen, prev, now) {
                Some(t) => m.insert(seat, t),
                None => m.remove(&seat),
            };
        }
    }
}

pub fn spawn(state: Arc<AppState>) {
    crate::managed_loop::ManagedLoop::new("seat_watch", INTERVAL_SECS)
        .startup_grace(STARTUP_GRACE_SECS)
        .spawn(state, move |state| async move {
            tick(&state).await;
            Ok(())
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_alert::{persisting_step, PersistState, Step};
    use serde_json::json;

    const T0: i64 = 1_800_000_000;

    fn hb(unit: &str) -> Value {
        json!({"kiosk_display": unit, "kiosk_serve": "active", "kiosk_bins": "home", "console_build": "stack-v0.6.25"})
    }

    /// Ticks every 60 s over (offset, kiosk.service state) samples, the seat
    /// heard at each tick; returns the acts in order. `open` is what the
    /// funnel holds: false until the first Raise.
    fn run(samples: &[(i64, &str)]) -> Vec<Act> {
        let mut first = None;
        let mut open = false;
        let mut acts = Vec::new();
        for &(off, unit) in samples {
            let now = T0 + off;
            let seen = seat_condition(Some(&hb(unit)), Some(now - 20), false, now);
            let a = display_act(&seen, first, open && matches!(seen, Seen::DisplayDown(_)), now);
            if a == Act::Raise {
                open = true;
            }
            if a == Act::Clear {
                open = false;
            }
            first = next_first_bad(&seen, first, now);
            acts.push(a);
        }
        acts
    }

    #[test]
    fn an_activating_display_pages_at_five_minutes_and_recovers_once() {
        let mut s: Vec<(i64, &str)> = (0..=6).map(|i| (i * 60, "activating")).collect();
        s.push((420, "active"));
        let acts = run(&s);
        assert_eq!(&acts[..5], &[Act::Wait; 5], "no alert before 5 min");
        assert_eq!(acts[5], Act::Raise, "one at 5 min");
        assert_eq!(acts[6], Act::Raise, "later ticks hand it to the funnel, whose schedule answers Quiet");
        assert_eq!(acts[7], Act::Clear, "the resolved line when it is back");
        // Later ticks are Quiet in the funnel, not a second onset:
        let a = display_alert("lobby", "activating", String::new());
        let (s1, st) = persisting_step(None, &a, T0 + 300, false);
        assert_eq!(s1, Step::Deliver(None));
        let (s2, _) = persisting_step(Some(st), &a, T0 + 360, false);
        assert_eq!(s2, Step::Quiet);
    }

    #[test]
    fn a_bundle_apply_that_restarts_the_display_within_five_minutes_never_pages() {
        // The roll: seat-sync applies the bundle and restarts kiosk.service;
        // it reports activating/inactive for a few minutes, then active.
        let acts = run(&[(0, "active"), (60, "activating"), (120, "inactive"), (180, "activating"), (300, "activating"), (359, "active"), (420, "active")]);
        assert!(!acts.contains(&Act::Raise), "{acts:?}");
    }

    #[test]
    fn a_gateway_restart_does_not_resend_the_onset_for_an_announced_seat() {
        // The debounce clock is gone (first_bad = None) but the funnel holds
        // the announced condition: the loop raises at once, and the funnel's
        // schedule, given the remembered state, answers Quiet.
        let now = T0 + 3600;
        let seen = seat_condition(Some(&hb("activating")), Some(now - 30), false, now);
        assert_eq!(display_act(&seen, None, true, now), Act::Raise);
        assert_eq!(display_act(&seen, None, false, now), Act::Wait, "not announced: the debounce starts over");
        let remembered = PersistState {
            kind: KIND_DISPLAY.into(),
            target: "lobby".into(),
            summary: String::new(),
            onset: T0,
            last_sent: T0,
            count: 1,
            muted_noted: false,
        };
        let (step, st) = persisting_step(Some(remembered), &display_alert("lobby", "activating", String::new()), now, false);
        assert_eq!(step, Step::Quiet, "no second onset after a restart");
        assert_eq!((st.onset, st.count), (T0, 1));
    }

    #[test]
    fn the_condition_follows_verifys_display_predicate() {
        let now = T0;
        let heard = Some(now - 30);
        assert_eq!(seat_condition(Some(&hb("activating")), heard, false, now), Seen::DisplayDown("activating".into()));
        assert_eq!(seat_condition(Some(&hb("failed")), heard, false, now), Seen::DisplayDown("failed".into()));
        assert_eq!(seat_condition(Some(&hb("active")), heard, false, now), Seen::Fine);
        let absent = json!({"kiosk_display": "inactive", "kiosk_bins": "absent"});
        assert_eq!(seat_condition(Some(&absent), heard, false, now), Seen::NoKiosk, "no kiosk set up");
        let unstated = json!({"kiosk_bins": "home"});
        assert_eq!(seat_condition(Some(&unstated), heard, false, now), Seen::NoKiosk);
        assert_eq!(seat_condition(None, heard, false, now), Seen::NoKiosk);
        assert_eq!(seat_condition(Some(&hb("activating")), heard, true, now), Seen::Gone);
        assert_eq!(seat_condition(Some(&hb("activating")), None, false, now), Seen::Unheard);
        assert_eq!(seat_condition(Some(&hb("activating")), Some(now - FRESH_SECS - 1), false, now), Seen::Stale);
        assert_eq!(seat_condition(Some(&hb("active")), Some(now - SILENT_SECS), false, now), Seen::Silent(SILENT_SECS));
    }

    #[test]
    fn a_silent_seat_pages_leaves_the_display_open_and_clears_when_back() {
        let now = T0;
        let silent = seat_condition(Some(&hb("activating")), Some(now - 900), false, now);
        assert_eq!(silent_act(&silent), Act::Raise);
        assert_eq!(display_act(&silent, Some(now - 900), true, now), Act::Leave, "unknown display: an open alert stays open");
        assert_eq!(next_first_bad(&silent, Some(now - 900), now), Some(now - 900));
        let stale = seat_condition(Some(&hb("active")), Some(now - 300), false, now);
        assert_eq!((display_act(&stale, None, false, now), silent_act(&stale)), (Act::Leave, Act::Clear));
        let back = seat_condition(Some(&hb("active")), Some(now - 10), false, now);
        assert_eq!((display_act(&back, None, false, now), silent_act(&back)), (Act::Clear, Act::Clear));
        assert_eq!(silent_act(&Seen::Unheard), Act::Leave);
    }

    #[test]
    fn a_revoked_seat_closes_both_conditions() {
        let gone = seat_condition(Some(&hb("activating")), Some(T0 - 5000), true, T0);
        assert_eq!((display_act(&gone, Some(T0 - 5000), true, T0), silent_act(&gone)), (Act::Clear, Act::Clear));
        assert_eq!(next_first_bad(&gone, Some(T0 - 5000), T0), None);
    }

    #[test]
    fn the_channel_says_the_repair_and_points_at_verify_unmasked() {
        // The rendered channel text, through the real scrubber: nothing in it
        // may be masked. (The first cut put the applier path in Next, and
        // the scrubber turned `noo-seat` into `[internal]`.)
        let a = display_alert("lobby", "activating", "kiosk.service=activating".into());
        let text = crate::egress::system(&a, "R-test");
        let t = text.as_str();
        assert!(t.contains("Seat 'lobby': the kiosk display is not running (state: activating)."), "{t}");
        assert!(t.contains("The repair is `kiosk seat-sync --migrate`, run as root on the seat"), "{t}");
        assert!(t.contains("Next: `noo cluster verify lobby`"), "{t}");
        assert!(!t.contains("kiosk.service=activating"), "detail is logged, never sent: {t}");
        assert!(!t.contains(crate::egress::MASK), "nothing masked: {t}");
        for alert in [silent_alert("lobby", 900), display_recovered("lobby"), silent_recovered("lobby")] {
            let r = crate::egress::system(&alert, "R-test");
            assert!(r.as_str().contains("Next: `noo cluster verify lobby`") && !r.as_str().contains(crate::egress::MASK), "{}", r.as_str());
        }
    }

    #[test]
    fn the_gateway_spawns_the_watch() {
        let main = include_str!("main.rs");
        assert!(main.contains("mod seat_watch;"));
        assert!(main.contains("seat_watch::spawn(state.clone());"));
    }
}
