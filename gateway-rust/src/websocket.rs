// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! WebSocket connection management + auth.
//!
//! Handles upgrade, JWT verification, connection registry,
//! and keepalive for both chat and collab WebSockets.

use axum::extract::ws::{Message, WebSocket};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth;

#[derive(Debug, Deserialize)]
pub struct WsParams {
    pub token: Option<String>,
}

/// Extract and verify JWT from WebSocket query params.
///
/// Fails CLOSED when the JWT secret is unconfigured (empty or the well-known
/// dev default): previously an empty secret granted an anonymous session to
/// every connection, and the default secret let anyone forge a valid token —
/// so `/ws/agent` peers and chat sockets were unauthenticated. We now reject
/// rather than trust a public secret. Configure `NOO_JWT_SECRET` to accept
/// WebSocket connections — there is no auth-disable bypass (auth is always
/// on; mint a dev token with the existing helpers instead).
pub fn verify_ws_auth(params: &WsParams, jwt_secret: &str) -> Result<auth::Claims, String> {
    if auth::jwt_secret_is_insecure(jwt_secret) {
        return Err("WebSocket auth unavailable: JWT secret not configured".into());
    }

    let token = params.token.as_deref().ok_or("No token provided")?;
    auth::verify_token(token, jwt_secret)
}

/// Clone-able, channel-backed writer for a WebSocket.
///
/// `run_streaming` used to hold `&mut WebSocket` for the whole turn, which
/// meant NOTHING else could write to the client mid-turn — exactly when an
/// exec-approval request needs to reach the originating dashboard tab
/// (#606's alert broadcast only ever reached OTHER tabs, whose select
/// loops were idle). Writes now flow through an unbounded mpsc into a
/// dedicated forwarder task that owns the sink; any holder of a clone
/// (the agent loop, the alert forwarder, `notify_exec_approval` via its
/// task-local) can emit frames concurrently, in send order.
#[derive(Clone)]
pub struct WsWriter {
    tx: tokio::sync::mpsc::UnboundedSender<Message>,
}

impl WsWriter {
    /// Split `socket` into a writer + forwarder. The returned JoinHandle
    /// finishes when every `WsWriter` clone is dropped or the peer goes
    /// away; the stream half is returned for the caller's read loop.
    pub fn spawn(
        socket: WebSocket,
    ) -> (
        Self,
        futures::stream::SplitStream<WebSocket>,
        tokio::task::JoinHandle<()>,
    ) {
        use futures::{SinkExt, StreamExt};
        let (mut sink, stream) = socket.split();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if sink.send(msg).await.is_err() {
                    break; // peer gone — drain-and-drop the rest
                }
            }
        });
        (WsWriter { tx }, stream, handle)
    }

    /// Queue a JSON value as a text frame. Returns false when the
    /// connection is gone (forwarder ended). Queueing is synchronous;
    /// these are `async fn` purely so call sites keep the exact shape of
    /// the old socket helpers (`.await` on every send).
    pub async fn send_json(&self, value: &Value) -> bool {
        match serde_json::to_string(value) {
            Ok(text) => self.tx.send(Message::Text(text.into())).is_ok(),
            Err(_) => false,
        }
    }

    /// Typed event with the same shaping rules as [`send_event`].
    pub async fn send_event(&self, event_type: &str, data: Value) -> bool {
        self.send_json(&shape_event(event_type, &data)).await
    }

    /// Queue a close frame with code 4401 behind whatever is already in
    /// flight, so a mid-turn session end still delivers the turn's frames.
    pub async fn send_close(&self, reason: &str) -> bool {
        self.tx.send(session_close_frame(reason)).is_ok()
    }

    pub async fn send_keepalive(&self) -> bool {
        self.send_json(&json!({"type": "keepalive"})).await
    }
}

/// Where a streaming turn's events go. The loop
/// emits `type`-discriminated JSON objects — `metadata`, `content`,
/// `thinking`, `tool_call`, `tool_result`, `done`, `error` — and never
/// cares what carries them. [`WsWriter`] is the dashboard socket;
/// [`NatsTurnSink`] is a node-hosted harness publishing to the gateway,
/// which relays onto the socket with [`relay_turn`].
#[allow(async_fn_in_trait)]
pub trait TurnSink: Sync {
    /// Queue one event. `false` = the far side is gone; the loop treats
    /// that as advisory, exactly as it treated a closed socket.
    async fn send_event(&self, event_type: &str, data: Value) -> bool;
}

impl TurnSink for WsWriter {
    async fn send_event(&self, event_type: &str, data: Value) -> bool {
        WsWriter::send_event(self, event_type, data).await
    }
}

/// The NATS subject a turn's events travel on: `harness.turn.<node>.<conversation>`.
///
/// The node comes FIRST, and it is the publisher's own id — the harness
/// puts its `NODE_ID` there, and the gateway subscribes to the subject of
/// the node it dispatched to. That is what makes the subject checkable by
/// the bus: the node grant is `harness.turn.<id>.>`, so a node holding only
/// its own credential cannot publish into a conversation another node is
/// serving. Before this the subject was
/// `harness.turn.<conversation>` under a `harness.turn.>` grant, and every
/// node could write assistant text and tool results into any transcript.
///
/// Both tokens go through the same replacement `ready_subject` uses. A `.`
/// in a node id is not cosmetic here: it would split the token and widen
/// what the grant written against `<id>` actually covers.
pub fn turn_subject(node: &str, conversation_id: &str) -> String {
    format!("harness.turn.{}.{}", subject_token(node), subject_token(conversation_id))
}

/// The pre-246 shape. The gateway still LISTENS on it for one release so a
/// harness that has not been upgraded over the rail keeps working; nothing
/// publishes it any more. Delete with the second subscription in
/// `dispatch::try_dispatch` once every node's harness is at noo-cli 0.5.41
/// or later — the release this shipped in.
pub fn legacy_turn_subject(conversation_id: &str) -> String {
    format!("harness.turn.{}", subject_token(conversation_id))
}

fn subject_token(s: &str) -> String {
    s.replace(['.', '*', '>', ' '], "_")
}

/// A turn sink that publishes each shaped event on a NATS subject.
pub struct NatsTurnSink {
    nats: async_nats::Client,
    subject: String,
}

impl NatsTurnSink {
    /// `node` is the publisher's OWN id (`NODE_ID` on the harness), never
    /// something the request told it — the subject has to name who is
    /// speaking, and the grant is what holds it to the truth.
    pub fn new(nats: async_nats::Client, node: &str, conversation_id: &str) -> Self {
        Self { nats, subject: turn_subject(node, conversation_id) }
    }
}

impl TurnSink for NatsTurnSink {
    async fn send_event(&self, event_type: &str, data: Value) -> bool {
        let bytes = match serde_json::to_vec(&shape_event(event_type, &data)) {
            Ok(b) => b,
            Err(_) => return false,
        };
        self.nats.publish(self.subject.clone(), bytes.into()).await.is_ok()
    }
}

/// The event a node-hosted harness publishes last: the whole
/// `CoordinatorResult`, for the gateway's non-streaming callers. Never
/// forwarded to a sink — the loop's own `done` already was.
pub const HARNESS_RESULT_EVENT: &str = "harness_result";

/// What the relay does with one event. Pure, so it is testable without a
/// bus: forward it, forward it and stop, swallow it and stop, or ignore.
#[derive(Debug, PartialEq)]
pub enum RelayStep {
    Forward,
    /// `error`: forward, then stop — there will be no result.
    ForwardAndStop,
    /// `harness_result`: keep, do not forward, stop.
    KeepAndStop,
}

pub fn relay_step(kind: &str, event: &Value) -> RelayStep {
    match kind {
        HARNESS_RESULT_EVENT => RelayStep::KeepAndStop,
        // A harness that says the turn never reached its model is asking
        // the gateway to run it instead: kept, so the socket sees the
        // answer, not a failure followed by an answer (i233).
        "error" if retry_safe(event) => RelayStep::KeepAndStop,
        "error" => RelayStep::ForwardAndStop,
        _ => RelayStep::Forward,
    }
}

/// `retry_safe: true` on a harness `error` event: the CLI was killed before
/// its first model call, so no tool ran and the gateway may run the turn.
pub fn retry_safe(event: &Value) -> bool {
    event.get("retry_safe").and_then(Value::as_bool) == Some(true)
}

/// How long to keep listening for the `harness_result` after `done` has
/// been forwarded: the harness sends it immediately after the loop
/// returns, so a longer wait only delays reporting a crashed harness.
const RESULT_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Forward a turn's events from its NATS subject onto `sink` until the
/// harness's result (or an `error`) arrives, the subscription ends, or
/// `deadline` passes. Returns the terminal event when there was one:
/// the `harness_result` event (with `result`) or the `error` event.
pub async fn relay_turn<S: TurnSink>(
    // A stream rather than one `Subscriber`: for the rollout window the
    // gateway listens on the scoped subject AND the legacy one, merged.
    mut sub: impl futures::Stream<Item = async_nats::Message> + Unpin,
    sink: &S,
    deadline: std::time::Duration,
) -> Option<Value> {
    use futures::StreamExt;
    let mut until = tokio::time::Instant::now() + deadline;
    loop {
        let msg = match tokio::time::timeout_at(until, sub.next()).await {
            Ok(Some(m)) => m,
            Ok(None) | Err(_) => return None,
        };
        let Ok(event) = serde_json::from_slice::<Value>(&msg.payload) else { continue };
        let kind = event.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
        let step = relay_step(&kind, &event);
        if step != RelayStep::KeepAndStop {
            // Re-shape without the discriminator so `shape_event` adds it
            // back exactly once, whatever the transport did to key order.
            let mut body = event.clone();
            if let Some(obj) = body.as_object_mut() {
                obj.remove("type");
            }
            let _ = sink.send_event(&kind, body).await;
        }
        match step {
            RelayStep::Forward => {
                if kind == "done" {
                    until = until.min(tokio::time::Instant::now() + RESULT_GRACE);
                }
            }
            RelayStep::ForwardAndStop | RelayStep::KeepAndStop => return Some(event),
        }
    }
}

/// A sink that keeps nothing: for turns whose caller wants only the
/// result (`coordinator::run` and friends dispatched to a node).
pub struct NullSink;

impl TurnSink for NullSink {
    async fn send_event(&self, _event_type: &str, _data: Value) -> bool {
        true
    }
}

/// Shared event shaping (see [`send_event`] for the contract).
fn shape_event(event_type: &str, data: &Value) -> Value {
    match data {
        Value::String(s) => json!({"type": event_type, "text": s}),
        Value::Object(map) => {
            let mut obj = serde_json::Map::new();
            obj.insert("type".into(), json!(event_type));
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
            Value::Object(obj)
        }
        other => json!({"type": event_type, "data": other}),
    }
}

/// Send a JSON message over WebSocket.
/// The close code both browser sockets use for "your credential is not
/// good here": a bad token at the handshake, the token's `exp` passing while
/// the socket is open, or a logout. The console refreshes once on it and
/// otherwise stops reconnecting (ws-protocol.md.
pub const CLOSE_SESSION_ENDED: u16 = 4401;

pub fn session_close_frame(reason: &str) -> Message {
    Message::Close(Some(axum::extract::ws::CloseFrame {
        code: CLOSE_SESSION_ENDED,
        reason: reason.to_string().into(),
    }))
}

/// When the token's `exp` (unix seconds) passes, as a tokio instant. An
/// already-expired token yields "now".
pub fn session_deadline(exp: usize) -> tokio::time::Instant {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let left = (exp as u64).saturating_sub(now);
    tokio::time::Instant::now() + std::time::Duration::from_secs(left)
}

/// Resolves when this socket's session is over: the token's `exp` passes,
/// or a logout ends every session for `sub`. A WebSocket authenticates
/// once, at the handshake; without this an open chat socket outlived the
/// 15-minute access token and the account's logout alike.
/// Returns the close reason.
pub async fn session_ended(
    exp: usize,
    sub: &str,
    mut ends: tokio::sync::broadcast::Receiver<String>,
) -> &'static str {
    let deadline = tokio::time::sleep_until(session_deadline(exp));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return "Token expired",
            ended = ends.recv() => match ended {
                Ok(who) if who == sub => return "Logged out",
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                // The hub is gone with the process; the deadline still applies.
                Err(_) => { deadline.as_mut().await; return "Token expired"; }
            },
        }
    }
}

/// Keeps a token-expiry close from landing in the middle of a turn.
///
/// The chat socket authenticates once, with a 15-minute access token, and
/// closes 4401 when it expires; the console refreshes and reconnects. Closing
/// on the dot cut off a turn that was still streaming, and the `error` frame
/// that preceded the close was written into whatever reply was last on
/// screen: a tab left open collected one "Token expired" line every 15
/// minutes (2026-10-16). Expiry now waits for the turn in flight, up to
/// [`TURN_GRACE`], and refuses to start a new one. A logout, or an admin
/// ending the account's sessions (`AlertHub::end_sessions`, same broadcast),
/// does not wait: it refuses new turns and [`revoked`] fires, which the
/// socket uses to drop the running turn — a disabled account does not get
/// to finish a long one.
///
/// [`revoked`]: TurnGate::revoked
#[derive(Default)]
pub struct TurnGate {
    /// (a turn is running, the session is ending, the session was revoked)
    state: std::sync::Mutex<(bool, bool, bool)>,
    idle: tokio::sync::Notify,
    revoke: tokio::sync::Notify,
}

/// The longest an expired session waits for the turn in flight.
pub const TURN_GRACE: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Held for the length of one turn; dropping it ends the turn.
pub struct TurnHeld<'a>(&'a TurnGate);

impl Drop for TurnHeld<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner()).0 = false;
        self.0.idle.notify_one();
    }
}

impl TurnGate {
    /// Start a turn. `None`: the session is ending, start nothing.
    pub fn begin(&self) -> Option<TurnHeld<'_>> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.1 {
            return None;
        }
        st.0 = true;
        Some(TurnHeld(self))
    }

    /// Mark the session ending and wait (at most `max`) for the running
    /// turn, if any, to finish.
    pub async fn finish_then_end(&self, max: std::time::Duration) {
        let deadline = tokio::time::Instant::now() + max;
        loop {
            let notified = self.idle.notified();
            {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                st.1 = true;
                if !st.0 {
                    return;
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return;
            }
        }
    }

    /// End the session now (a logout or an admin end): no new turns, and
    /// [`TurnGate::revoked`] fires for the turn in flight.
    pub fn end_now(&self) {
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.1 = true;
            st.2 = true;
        }
        self.revoke.notify_waiters();
    }

    /// Resolves once [`TurnGate::end_now`] has run (never on expiry).
    pub async fn revoked(&self) {
        let notified = self.revoke.notified();
        if self.state.lock().unwrap_or_else(|e| e.into_inner()).2 {
            return;
        }
        notified.await;
    }
}

pub async fn send_json(socket: &mut WebSocket, value: &Value) -> bool {
    let text = match serde_json::to_string(value) {
        Ok(t) => t,
        Err(_) => return false,
    };
    socket.send(Message::Text(text.into())).await.is_ok()
}

/// Send a typed event over WebSocket (matches Python StreamEvent format).
pub async fn send_event(socket: &mut WebSocket, event_type: &str, data: Value) -> bool {
    // Chat.js expects flat events: {"type":"content","text":"..."} not {"type":"content","data":"..."}
    // For string data (content, error, thinking): put in "text" field
    // For object data (metadata, done, tool_call, tool_result): spread fields at top level
    send_json(socket, &shape_event(event_type, &data)).await
}

/// Send a keepalive ping.
pub async fn send_keepalive(socket: &mut WebSocket) -> bool {
    send_json(socket, &json!({"type": "keepalive"})).await
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    #[test]
    fn relay_forwards_everything_but_the_result_and_stops_on_it_or_error() {
        assert_eq!(relay_step("content", &json!({})), RelayStep::Forward);
        assert_eq!(relay_step("done", &json!({})), RelayStep::Forward);
        assert_eq!(relay_step("tool_call", &json!({})), RelayStep::Forward);
        assert_eq!(relay_step("error", &json!({"text": "boom"})), RelayStep::ForwardAndStop);
        assert_eq!(relay_step("error", &json!({"text": "stalled", "retry_safe": true})), RelayStep::KeepAndStop, "a retry-safe error is kept for the gateway to run the turn");
        assert_eq!(relay_step("error", &json!({"text": "x", "retry_safe": false})), RelayStep::ForwardAndStop);
        assert_eq!(relay_step(HARNESS_RESULT_EVENT, &json!({})), RelayStep::KeepAndStop);
    }

    #[test]
    fn turn_subjects_never_carry_subject_syntax() {
        assert_eq!(turn_subject("host3", "abc-123"), "harness.turn.host3.abc-123");
        assert_eq!(turn_subject("host3", "a.b*c>d e"), "harness.turn.host3.a_b_c_d_e");
        assert_eq!(legacy_turn_subject("a.b*c>d e"), "harness.turn.a_b_c_d_e");
    }

    /// The node token is what the grant is written against. A node id with
    /// a `.` in it must not become two tokens, or `harness.turn.<id>.>`
    /// would cover a different subject than the one actually published.
    #[test]
    fn a_dot_in_the_node_id_cannot_widen_the_grant() {
        let subj = turn_subject("edge.a", "conv");
        assert_eq!(subj, "harness.turn.edge_a.conv");
        assert_eq!(subj.split('.').count(), 4, "node and conversation are exactly one token each");
    }

    /// The node comes first so the bus can check it; the conversation can be
    /// anything and it is not the publisher's identity.
    #[test]
    fn the_node_is_the_first_token_after_the_prefix() {
        let subj = turn_subject("host3", "conv-1");
        assert_eq!(subj.strip_prefix("harness.turn.").and_then(|r| r.split('.').next()), Some("host3"));
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn now() -> usize {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_token_ends_the_session_at_once() {
        let (tx, rx) = tokio::sync::broadcast::channel(4);
        let _keep = tx;
        assert_eq!(session_ended(now() - 1, "alice", rx).await, "Token expired");
    }

    #[tokio::test(start_paused = true)]
    async fn a_logout_for_this_subject_ends_it_and_another_subjects_does_not() {
        let (tx, rx) = tokio::sync::broadcast::channel(4);
        let fut = tokio::spawn(session_ended(now() + 3600, "alice", rx));
        tx.send("bob".to_string()).unwrap();
        tokio::task::yield_now().await;
        assert!(!fut.is_finished(), "bob's logout must not close alice's socket");
        tx.send("alice".to_string()).unwrap();
        assert_eq!(fut.await.unwrap(), "Logged out");
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_waits_for_the_turn_in_flight() {
        let gate = std::sync::Arc::new(TurnGate::default());
        let held = gate.begin().expect("a turn starts");
        let g = gate.clone();
        let ending = tokio::spawn(async move { g.finish_then_end(TURN_GRACE).await });
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        assert!(!ending.is_finished(), "the close must not cut a running turn off");
        assert!(gate.begin().is_none(), "no new turn once the session is ending");
        drop(held);
        ending.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_with_no_turn_ends_at_once_and_a_stuck_turn_is_capped() {
        let idle = TurnGate::default();
        idle.finish_then_end(TURN_GRACE).await;
        assert!(idle.begin().is_none());

        let stuck = TurnGate::default();
        let _held = stuck.begin().unwrap();
        let t0 = tokio::time::Instant::now();
        stuck.finish_then_end(TURN_GRACE).await;
        assert_eq!(t0.elapsed(), TURN_GRACE);
    }

    #[tokio::test]
    async fn a_logout_refuses_new_turns_and_revokes_the_running_one() {
        let gate = std::sync::Arc::new(TurnGate::default());
        let _held = gate.begin().unwrap();
        let g = gate.clone();
        let watcher = tokio::spawn(async move { g.revoked().await });
        tokio::task::yield_now().await;
        assert!(!watcher.is_finished());
        gate.end_now();
        watcher.await.unwrap();
        assert!(gate.begin().is_none());
        // Already revoked: resolves at once.
        gate.revoked().await;
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_never_revokes() {
        let gate = TurnGate::default();
        gate.finish_then_end(TURN_GRACE).await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(1), gate.revoked()).await;
        assert!(r.is_err(), "expiry lets the turn finish; only a logout revokes");
    }

    #[test]
    fn the_close_frame_carries_4401() {
        match session_close_frame("Token expired") {
            Message::Close(Some(f)) => {
                assert_eq!(f.code, 4401);
                assert_eq!(f.reason.as_str(), "Token expired");
            }
            other => panic!("not a close frame: {other:?}"),
        }
    }
}
