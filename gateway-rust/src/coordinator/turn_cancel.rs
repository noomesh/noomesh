// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Telling a node's harness to stop a turn the gateway has abandoned.
//!
//! A turn handed to a harness keeps running on the node (its model call and
//! its tool loop, holding one of the node's slots) after the gateway drops
//! it: the console tab closed, the HTTP client went away, a session was
//! revoked, or the deadline passed. Dropping the gateway's wait only drops
//! the bus subscription; nothing reached the node.
//!
//! The carrier is the subject the harness already listens on,
//! `harness.run.<node>`: the gateway already publishes there and the node's
//! principal already subscribes there, so no bus grant changes and a node
//! enrolled before this existed needs no re-provisioning. The message is
//! `{"kind": "cancel", "turn_id": "<id>"}`. A turn request carries a
//! `turn_id` too (a random v4 UUID the gateway made for that one dispatch).
//!
//! What a cancel stops. A turn run by the vendor-CLI driver gets a cancel
//! signal ([`cancelled`]) the driver waits on beside the CLI: it kills the
//! CLI's whole process group (the code the timeout uses), then falls through
//! the same end-of-turn cleanup a finished turn runs (door key revoked,
//! config files and workspace removed, usage reported). A hard abort follows
//! only if the task has not ended within [`CANCEL_GRACE`]. A turn run by the
//! in-process loop has nothing to clean up on the node and is aborted at once
//! (its model request is dropped with it).
//!
//! Mixed versions:
//!
//! - New gateway, old harness: the old harness parses every payload on the
//!   subject as a `TurnRequest`; a cancel lacks `prompt`, `channel`,
//!   `user`, `token`, so it fails to parse, is logged as unreadable and
//!   dropped. It never becomes a turn. It gets no reply because a cancel is
//!   a plain publish, not a request.
//! - Old gateway, new harness: the request has no `turn_id`, the turn is not
//!   registered, and nothing ever sends a cancel. As before.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde_json::{json, Value};
use std::time::Duration;

use tokio::sync::{watch, OwnedSemaphorePermit};
use tokio::task::AbortHandle;

use super::TurnRequest;

/// The `kind` of a cancel message on `harness.run.<node>`.
pub const CANCEL_KIND: &str = "cancel";

/// How long a cancelled driver turn has to clean up (kill the CLI group,
/// revoke its door key, remove its files) before it is aborted outright.
pub const CANCEL_GRACE: Duration = Duration::from_secs(15);

tokio::task_local! {
    /// The cancel signal of the turn this task runs (set by [`spawn_tracked`]).
    static CANCEL: watch::Receiver<bool>;
}

/// Resolves when the turn this task runs is cancelled; never resolves for a
/// task that is not a tracked turn, or whose turn ends without a cancel.
pub async fn cancelled() {
    let Ok(mut rx) = CANCEL.try_with(Clone::clone) else {
        return std::future::pending().await;
    };
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

/// Whether the turn this task runs has been cancelled.
pub fn is_cancelled() -> bool {
    CANCEL.try_with(|rx| *rx.borrow()).unwrap_or(false)
}

/// A fresh, unguessable id for one dispatch.
pub fn new_turn_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The payload that cancels the turn `turn_id`.
pub fn cancel_message(turn_id: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"kind": CANCEL_KIND, "turn_id": turn_id})).unwrap_or_default()
}

/// What a payload on `harness.run.<node>` is.
#[derive(Debug, PartialEq)]
pub enum Inbound {
    Turn(Box<TurnRequest>),
    Cancel(String),
    Unreadable(String),
}

/// Sort a payload: a cancel names its `turn_id`; anything else must parse
/// as a [`TurnRequest`] exactly as before.
pub fn parse_inbound(payload: &[u8]) -> Inbound {
    let v: Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => return Inbound::Unreadable(e.to_string()),
    };
    if v.get("kind").and_then(Value::as_str) == Some(CANCEL_KIND) {
        return match v.get("turn_id").and_then(Value::as_str).filter(|id| !id.is_empty()) {
            Some(id) => Inbound::Cancel(id.to_string()),
            None => Inbound::Unreadable("cancel without a turn_id".to_string()),
        };
    }
    match serde_json::from_value::<TurnRequest>(v) {
        Ok(r) => Inbound::Turn(Box::new(r)),
        Err(e) => Inbound::Unreadable(e.to_string()),
    }
}

/// Run `fut` on the current runtime, if there is one. A Drop may run with
/// no runtime (a test, a shutdown): then nothing is sent and nothing
/// panics. Returns whether the work was spawned.
pub fn spawn_detached<Fut>(fut: Fut) -> bool
where
    Fut: Future<Output = ()> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(rt) => {
            rt.spawn(fut);
            true
        }
        Err(_) => false,
    }
}

/// Publish `payload` on `subject` without waiting, from a sync context.
pub fn publish_detached(nats: async_nats::Client, subject: String, payload: Vec<u8>) {
    spawn_detached(async move {
        let _ = nats.publish(subject, payload.into()).await;
    });
}

/// Armed when a turn is handed to a harness. If it is dropped still armed
/// (the caller's future was dropped, or the turn timed out), it sends one
/// cancel for the turn through `send`. [`CancelGuard::disarm`] ends it
/// quietly: the turn ended with a terminal event, or was never taken.
pub struct CancelGuard<F: FnOnce(Vec<u8>)> {
    turn_id: String,
    send: Option<F>,
}

impl<F: FnOnce(Vec<u8>)> CancelGuard<F> {
    pub fn new(turn_id: String, send: F) -> Self {
        Self { turn_id, send: Some(send) }
    }

    pub fn disarm(&mut self) {
        self.send = None;
    }
}

impl<F: FnOnce(Vec<u8>)> Drop for CancelGuard<F> {
    fn drop(&mut self) {
        if let Some(send) = self.send.take() {
            let payload = cancel_message(&self.turn_id);
            // A Drop must never panic (it may already be unwinding).
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| send(payload)));
        }
    }
}

/// The guard for a dispatch to `node`: on drop it hands `publish` the
/// request's subject (`harness.run.<node>`) and the cancel payload.
pub fn guard_for<P: FnOnce(String, Vec<u8>)>(turn_id: String, node: &str, publish: P) -> CancelGuard<impl FnOnce(Vec<u8>)> {
    let subject = super::harness_run_subject(node);
    CancelGuard::new(turn_id, move |payload| publish(subject, payload))
}

/// Disarm the guard only when the turn produced a terminal event. No
/// terminal event (the deadline passed) leaves it armed, so the node is told.
pub fn disarm_on_terminal<F: FnOnce(Vec<u8>), T>(guard: &mut CancelGuard<F>, terminal: Option<&T>) {
    if terminal.is_some() {
        guard.disarm();
    }
}

/// The harness's running turns by turn id, to stop the one a cancel names.
#[derive(Default)]
pub struct TurnRegistry {
    turns: Mutex<HashMap<String, Running>>,
}

struct Running {
    abort: AbortHandle,
    signal: watch::Sender<bool>,
    /// The turn cleans up after itself on the signal; abort only as a backstop.
    graceful: bool,
}

impl TurnRegistry {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Running>> {
        self.turns.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn insert(&self, id: String, running: Running) {
        self.lock().insert(id, running);
    }

    fn remove(&self, id: &str) {
        self.lock().remove(id);
    }

    /// Stop the turn named `id`. `false` when no such turn is running (it
    /// finished, was already cancelled, or never was here): nothing happens.
    pub fn cancel(&self, id: &str) -> bool {
        let Some(running) = self.lock().remove(id) else { return false };
        if running.graceful {
            let _ = running.signal.send(true);
            let abort = running.abort.clone();
            let backstop = async move {
                tokio::time::sleep(CANCEL_GRACE).await;
                abort.abort();
            };
            if !spawn_detached(backstop) {
                running.abort.abort();
            }
        } else {
            running.abort.abort();
        }
        true
    }

    pub fn running(&self) -> usize {
        self.lock().len()
    }
}

/// What the harness does with one payload on `harness.run.<node>`.
#[derive(Debug, PartialEq)]
pub enum Handled {
    /// A turn to take.
    Turn(Box<TurnRequest>),
    /// A cancel that stopped the named running turn.
    Cancelled(String),
    /// Unreadable, or a cancel for a turn not running here: nothing to do.
    Ignored,
}

/// The harness's one entry for an inbound payload: a cancel is applied to
/// `registry`, a turn is handed back, anything else is logged and ignored.
pub fn handle_inbound(registry: &TurnRegistry, payload: &[u8]) -> Handled {
    match parse_inbound(payload) {
        Inbound::Turn(r) => Handled::Turn(r),
        Inbound::Cancel(id) => {
            if registry.cancel(&id) {
                Handled::Cancelled(id)
            } else {
                Handled::Ignored
            }
        }
        Inbound::Unreadable(e) => {
            tracing::warn!(error = %e, "harness: unreadable turn request");
            Handled::Ignored
        }
    }
}

/// Removes its turn from the registry however the turn's task ends: it
/// finished, failed, or was aborted (the future is dropped, so this drops).
struct TurnEntry {
    registry: Arc<TurnRegistry>,
    id: Option<String>,
}

impl Drop for TurnEntry {
    fn drop(&mut self) {
        if let Some(id) = &self.id {
            self.registry.remove(id);
        }
    }
}

/// Spawn one turn's task, holding `permit` for its whole life, registered
/// under `turn_id` (when the request carried one) so [`TurnRegistry::cancel`]
/// can stop it. `graceful` = the work watches [`cancelled`] and cleans up
/// itself (the driver); otherwise a cancel aborts the task at once. The
/// permit and the registry entry are owned by the task's future, so
/// finishing, failing and being aborted all release both through the same
/// drop. The task waits for its registration before it starts, so a turn
/// that ends at once cannot leave a stale entry behind.
pub fn spawn_tracked<Fut>(
    registry: &Arc<TurnRegistry>,
    turn_id: Option<String>,
    graceful: bool,
    permit: OwnedSemaphorePermit,
    work: Fut,
) -> tokio::task::JoinHandle<()>
where
    Fut: Future<Output = ()> + Send + 'static,
{
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let (signal, rx) = watch::channel(false);
    let entry = TurnEntry { registry: registry.clone(), id: turn_id.clone() };
    let job = tokio::spawn(CANCEL.scope(rx, async move {
        let _ = go_rx.await;
        let _permit = permit;
        let _entry = entry;
        work.await;
    }));
    if let Some(id) = turn_id {
        registry.insert(id, Running { abort: job.abort_handle(), signal, graceful });
    }
    let _ = go_tx.send(());
    job
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::Semaphore;

    fn sample_turn(turn_id: Option<&str>) -> TurnRequest {
        TurnRequest {
            conversation_id: "c1".into(),
            prompt: "hi".into(),
            channel: "dashboard".into(),
            max_iterations: 5,
            model: None,
            user: "alice".into(),
            enable_thinking: false,
            role_prompt: None,
            stream: false,
            token: "t".into(),
            turn_id: turn_id.map(str::to_string),
        }
    }

    fn recording_guard(turn_id: &str) -> (CancelGuard<impl FnOnce(Vec<u8>)>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let sink = sent.clone();
        let guard = CancelGuard::new(turn_id.to_string(), move |p| sink.lock().unwrap().push(p));
        (guard, sent)
    }

    #[test]
    fn a_dropped_armed_guard_sends_exactly_one_cancel_naming_the_turn() {
        let (guard, sent) = recording_guard("turn-a");
        drop(guard);
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(parse_inbound(&sent[0]), Inbound::Cancel("turn-a".to_string()));
    }

    #[test]
    fn a_disarmed_guard_sends_nothing() {
        // A normal end and an error end both reach the terminal event and
        // disarm; a refusal disarms too.
        let (mut guard, sent) = recording_guard("turn-a");
        guard.disarm();
        drop(guard);
        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn the_guard_does_not_panic_when_the_sender_does() {
        let guard = CancelGuard::new("turn-a".to_string(), |_p: Vec<u8>| panic!("bus gone"));
        drop(guard);
    }

    #[test]
    fn publishing_with_no_runtime_is_a_quiet_no_op() {
        // A Drop on a thread with no runtime (shutdown finished) must not panic.
        assert!(!spawn_detached(async {}));
    }

    #[tokio::test]
    async fn publishing_inside_a_runtime_spawns_the_work() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        assert!(spawn_detached(async move {
            let _ = tx.send(7);
        }));
        assert_eq!(rx.await.unwrap(), 7);
    }

    #[test]
    fn an_old_shape_turn_still_parses_as_a_turn_and_a_cancel_is_never_one() {
        // No turn_id, no kind: what an old gateway sends.
        let old = json!({
            "conversation_id": "c1", "prompt": "hi", "channel": "dashboard", "max_iterations": 5,
            "user": "alice", "token": "t"
        });
        match parse_inbound(&serde_json::to_vec(&old).unwrap()) {
            Inbound::Turn(t) => assert_eq!(*t, sample_turn(None)),
            other => panic!("an old-shape request must stay a turn: {other:?}"),
        }
        // The new shape round-trips with its id.
        let new = serde_json::to_vec(&sample_turn(Some("turn-a"))).unwrap();
        assert!(matches!(parse_inbound(&new), Inbound::Turn(t) if t.turn_id.as_deref() == Some("turn-a")));
        // A cancel is not a TurnRequest: an OLD harness, which parses every
        // payload as one, rejects it instead of starting a turn.
        assert!(serde_json::from_slice::<TurnRequest>(&cancel_message("turn-a")).is_err());
        // Malformed cancels and junk are unreadable, never a turn.
        assert!(matches!(parse_inbound(br#"{"kind":"cancel"}"#), Inbound::Unreadable(_)));
        assert!(matches!(parse_inbound(br#"{"kind":"cancel","turn_id":""}"#), Inbound::Unreadable(_)));
        assert!(matches!(parse_inbound(b"not json"), Inbound::Unreadable(_)));
    }

    #[test]
    fn a_turn_request_without_an_id_leaves_it_off_the_wire() {
        let v = serde_json::to_value(sample_turn(None)).unwrap();
        assert!(v.get("turn_id").is_none());
    }

    #[test]
    fn turn_ids_are_random_per_dispatch() {
        assert_ne!(new_turn_id(), new_turn_id());
        assert_eq!(new_turn_id().len(), 36);
    }

    async fn settle(job: tokio::task::JoinHandle<()>) -> bool {
        job.await.is_err()
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancel_aborts_the_named_turn_and_releases_its_slot() {
        let slots = Arc::new(Semaphore::new(2));
        let reg = Arc::new(TurnRegistry::default());
        let permit = slots.clone().try_acquire_owned().unwrap();
        let job = spawn_tracked(&reg, Some("turn-a".into()), false, permit, async {
            tokio::time::sleep(Duration::from_secs(900)).await;
        });
        tokio::task::yield_now().await;
        assert_eq!((slots.available_permits(), reg.running()), (1, 1), "the turn holds one slot");
        assert!(reg.cancel("turn-a"));
        assert!(settle(job).await, "the task was aborted, not finished");
        assert_eq!(slots.available_permits(), 2, "the slot is back");
        assert_eq!(reg.running(), 0, "no stale entry");
        // A second cancel, and an id nobody holds, do nothing.
        assert!(!reg.cancel("turn-a"));
        assert!(!reg.cancel("nobody"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancel_never_touches_a_different_turn() {
        let slots = Arc::new(Semaphore::new(2));
        let reg = Arc::new(TurnRegistry::default());
        let a = spawn_tracked(&reg, Some("turn-a".into()), false, slots.clone().try_acquire_owned().unwrap(), async {
            tokio::time::sleep(Duration::from_secs(900)).await;
        });
        let b = spawn_tracked(&reg, Some("turn-b".into()), false, slots.clone().try_acquire_owned().unwrap(), async {
            tokio::time::sleep(Duration::from_secs(900)).await;
        });
        tokio::task::yield_now().await;
        assert!(reg.cancel("turn-a"));
        assert!(settle(a).await);
        assert_eq!((slots.available_permits(), reg.running()), (1, 1), "turn-b still runs and holds its slot");
        assert!(!b.is_finished());
        // The other turn finishes on its own and releases the same way.
        tokio::time::advance(Duration::from_secs(901)).await;
        assert!(!settle(b).await, "turn-b ran to its end");
        assert_eq!((slots.available_permits(), reg.running()), (2, 0));
    }

    #[tokio::test]
    async fn a_finished_turn_leaves_nothing_and_a_late_cancel_is_ignored() {
        let slots = Arc::new(Semaphore::new(1));
        let reg = Arc::new(TurnRegistry::default());
        let job = spawn_tracked(&reg, Some("turn-a".into()), false, slots.clone().try_acquire_owned().unwrap(), async {});
        assert!(!settle(job).await);
        assert_eq!((slots.available_permits(), reg.running()), (1, 0));
        assert!(!reg.cancel("turn-a"));
    }

    #[tokio::test]
    async fn a_turn_without_an_id_is_never_registered_or_cancellable() {
        let slots = Arc::new(Semaphore::new(1));
        let reg = Arc::new(TurnRegistry::default());
        let job = spawn_tracked(&reg, None, false, slots.clone().try_acquire_owned().unwrap(), async {
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(reg.running(), 0);
        assert!(!reg.cancel(""));
        assert!(!job.is_finished());
        job.abort();
        assert!(settle(job).await);
        assert_eq!(slots.available_permits(), 1);
    }

    #[test]
    fn the_cancel_wire_literal_is_pinned() {
        assert_eq!(String::from_utf8(cancel_message("abc")).unwrap(), r#"{"kind":"cancel","turn_id":"abc"}"#);
        assert_eq!(CANCEL_KIND, "cancel");
    }

    #[test]
    fn dropping_an_armed_guard_publishes_on_the_requests_subject_with_the_turn_id() {
        let seen: Arc<Mutex<Vec<(String, Vec<u8>)>>> = Arc::default();
        let sink = seen.clone();
        let guard = guard_for("turn-a".to_string(), "host8", move |subject, payload| sink.lock().unwrap().push((subject, payload)));
        assert!(seen.lock().unwrap().is_empty(), "nothing is sent while the turn runs");
        drop(guard);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, super::super::harness_run_subject("host8"));
        assert_eq!(seen[0].0, "harness.run.host8");
        assert_eq!(seen[0].1, cancel_message("turn-a"));
    }

    #[test]
    fn the_guard_is_disarmed_only_by_a_terminal_event() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let mk = |seen: &Arc<Mutex<Vec<String>>>| {
            let sink = seen.clone();
            guard_for("turn-a".to_string(), "n", move |subject, _| sink.lock().unwrap().push(subject))
        };
        // The deadline passed: no terminal event, so the cancel still goes.
        let mut g = mk(&seen);
        disarm_on_terminal(&mut g, None::<&Value>);
        drop(g);
        assert_eq!(seen.lock().unwrap().len(), 1, "a deadline end still cancels");
        // A terminal event (result or error): nothing is sent.
        let mut g = mk(&seen);
        disarm_on_terminal(&mut g, Some(&json!({"type": "harness_result"})));
        drop(g);
        assert_eq!(seen.lock().unwrap().len(), 1, "a normal end sends no cancel");
    }

    #[tokio::test(start_paused = true)]
    async fn a_turn_taken_with_an_id_is_cancelled_end_to_end_through_the_inbound_handler() {
        let slots = Arc::new(Semaphore::new(1));
        let reg = Arc::new(TurnRegistry::default());
        let payload = serde_json::to_vec(&sample_turn(Some("turn-a"))).unwrap();
        let Handled::Turn(req) = handle_inbound(&reg, &payload) else { panic!("a turn request is a turn") };
        let job = spawn_tracked(&reg, req.turn_id.clone(), false, slots.clone().try_acquire_owned().unwrap(), async {
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(reg.running(), 1);
        // Another turn's id, junk and an id-less cancel change nothing.
        assert_eq!(handle_inbound(&reg, &cancel_message("turn-b")), Handled::Ignored);
        assert_eq!(handle_inbound(&reg, b"junk"), Handled::Ignored);
        assert_eq!(reg.running(), 1);
        assert_eq!(handle_inbound(&reg, &cancel_message("turn-a")), Handled::Cancelled("turn-a".to_string()));
        assert!(settle(job).await);
        assert_eq!((slots.available_permits(), reg.running()), (1, 0));
        assert_eq!(handle_inbound(&reg, &cancel_message("turn-a")), Handled::Ignored, "a second cancel is ignored");
    }

    #[tokio::test(start_paused = true)]
    async fn a_graceful_turn_is_signalled_and_ends_itself_before_the_backstop() {
        let slots = Arc::new(Semaphore::new(1));
        let reg = Arc::new(TurnRegistry::default());
        let cleaned = Arc::new(Mutex::new(false));
        let flag = cleaned.clone();
        let job = spawn_tracked(&reg, Some("turn-a".into()), true, slots.clone().try_acquire_owned().unwrap(), async move {
            assert!(!is_cancelled());
            cancelled().await;
            assert!(is_cancelled());
            // Its own cleanup runs after the signal, as the driver's does.
            tokio::time::sleep(Duration::from_secs(2)).await;
            *flag.lock().unwrap() = true;
        });
        tokio::task::yield_now().await;
        assert!(reg.cancel("turn-a"));
        assert!(!settle(job).await, "it ended by itself, not by abort");
        assert!(*cleaned.lock().unwrap(), "its cleanup ran to the end");
        assert_eq!((slots.available_permits(), reg.running()), (1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_graceful_turn_that_ignores_the_signal_is_aborted_after_the_grace() {
        let slots = Arc::new(Semaphore::new(1));
        let reg = Arc::new(TurnRegistry::default());
        let job = spawn_tracked(&reg, Some("turn-a".into()), true, slots.clone().try_acquire_owned().unwrap(), async {
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert!(reg.cancel("turn-a"));
        tokio::time::advance(CANCEL_GRACE - Duration::from_secs(1)).await;
        assert!(!job.is_finished(), "still within the grace");
        assert!(settle(job).await, "aborted at the grace");
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn outside_a_tracked_turn_nothing_is_cancelled() {
        assert!(!is_cancelled());
        assert!(tokio::time::timeout(Duration::from_millis(20), cancelled()).await.is_err());
    }

    #[test]
    fn the_wiring_is_in_the_dispatch_and_the_harness() {
        let dispatch = include_str!("dispatch.rs");
        let body = crate::test_src::fn_body(dispatch, "pub async fn try_dispatch");
        assert!(body.contains("turn_cancel::guard_for(turn_id, &node,"), "try_dispatch arms a guard for the request's node");
        assert!(body.contains("turn_id: Some(turn_id.clone())"), "the request carries the turn id");
        assert_eq!(body.matches("cancel.disarm();").count(), 2, "refused and no responder");
        assert!(body.contains("turn_cancel::disarm_on_terminal(&mut cancel, terminal.as_ref());"));
        let terminal = body.find("relay_turn(events, sink, deadline).await").unwrap();
        let disarm = body.find("disarm_on_terminal").unwrap();
        assert!(terminal < disarm, "the guard stays armed until the terminal event");
        let harness = include_str!("../harness_main.rs");
        let run = crate::test_src::fn_body(harness, "pub async fn run()");
        assert!(run.contains("turn_cancel::handle_inbound(&running_turns, &msg.payload)"));
        assert!(
            run.contains("turn_cancel::spawn_tracked(&running_turns, req.turn_id.clone(), driver.is_some(), permit,"),
            "the request's turn id and the driver's graceful stop reach the registry"
        );
    }
}
