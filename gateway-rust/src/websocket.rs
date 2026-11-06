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
    /// A JWT in the URL. Only `/ws/agent` (a peer token) still takes one;
    /// the console sockets refuse it (i515c).
    pub token: Option<String>,
    /// A single-use ticket from `POST /api/ws-ticket` (console sockets).
    pub ticket: Option<String>,
}

/// The console's sockets: opened with a single-use ticket, never a JWT in the
/// URL, where it would land in proxy logs and browser history (i515c).
pub const TICKET_SOCKETS: &[&str] = &["/ws/coordinator", "/ws/collab"];
/// Where a browser mints a ticket for one of [`TICKET_SOCKETS`].
pub const WS_TICKET_PATH: &str = "/api/ws-ticket";
/// How long a ticket may wait to be used.
pub const WS_TICKET_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// Unredeemed tickets kept at most: a flood of mints cannot grow memory.
const MAX_WS_TICKETS: usize = 10_000;

struct CoreTicket {
    claims: auth::Claims,
    socket: String,
    expires: std::time::Instant,
}

static CORE_TICKETS: std::sync::Mutex<Option<std::collections::HashMap<String, CoreTicket>>> =
    std::sync::Mutex::new(None);

/// Mint a single-use ticket for `socket`, standing for the verified `claims`.
/// 244 random bits (two v4 UUIDs), valid [`WS_TICKET_TTL`].
pub fn mint_ws_ticket(claims: auth::Claims, socket: &str) -> String {
    let id = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let mut guard = CORE_TICKETS.lock().unwrap_or_else(|p| p.into_inner());
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let now = std::time::Instant::now();
    map.retain(|_, t| t.expires > now);
    if map.len() >= MAX_WS_TICKETS {
        // The closed answer: outstanding tickets fail, their pages mint again.
        map.clear();
    }
    map.insert(id.clone(), CoreTicket { claims, socket: socket.to_string(), expires: now + WS_TICKET_TTL });
    id
}

/// Redeem a ticket for `socket`. Single use: the ticket is removed whether or
/// not it matches, so it can be tried exactly once.
fn redeem_ws_ticket(ticket: &str, socket: &str) -> Option<auth::Claims> {
    let mut guard = CORE_TICKETS.lock().unwrap_or_else(|p| p.into_inner());
    let t = guard.as_mut()?.remove(ticket)?;
    (t.expires > std::time::Instant::now() && t.socket == socket).then_some(t.claims)
}

/// Authenticate a console socket handshake (`/ws/coordinator`, `/ws/collab`)
/// from its single-use ticket. A JWT in the URL is refused with the way to
/// do it instead: there is no fallback to `?token=` (i515c).
pub fn verify_ws_ticket(params: &WsParams, socket: &str, jwt_secret: &str) -> Result<auth::Claims, String> {
    if auth::jwt_secret_is_insecure(jwt_secret) {
        return Err("WebSocket auth unavailable: JWT secret not configured".into());
    }
    let Some(ticket) = params.ticket.as_deref().filter(|t| !t.is_empty()) else {
        return Err(if params.token.is_some() {
            format!("{socket} no longer takes ?token=: mint a single-use ticket (POST {WS_TICKET_PATH}) and connect with ?ticket=")
        } else {
            "No ticket provided".into()
        });
    };
    let claims = redeem_ws_ticket(ticket, socket).ok_or("ticket unknown, already used, expired, or for another socket")?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(u64::MAX);
    if (claims.exp as u64) <= now {
        return Err("the access token behind this ticket has expired".into());
    }
    Ok(claims)
}

#[derive(Debug, Deserialize)]
pub struct WsTicketBody {
    pub socket: String,
}

/// POST /api/ws-ticket — `{socket}`: a single-use ticket for opening one of the console's sockets (`/ws/coordinator`, `/ws/collab`) from a browser, which cannot send an Authorization header on a WebSocket. Send the access token as `Authorization: Bearer`; open `<socket>?ticket=<ticket>` within 30 seconds. The ticket is bound to this person and this socket and is consumed by the first handshake that presents it. A delegated or harness credential cannot mint one.
pub async fn ws_ticket(
    headers: axum::http::HeaderMap,
    ctx: Option<axum::Extension<auth::RequesterCtx>>,
    axum::Json(body): axum::Json<WsTicketBody>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let refuse = |code: StatusCode, msg: String| (code, axum::Json(json!({ "error": msg }))).into_response();
    let Some(axum::Extension(r)) = ctx else {
        return refuse(StatusCode::UNAUTHORIZED, "a socket ticket is for a signed-in person; no verified caller".into());
    };
    if r.act.is_some() || r.harness.is_some() {
        return refuse(StatusCode::FORBIDDEN, "a delegated or harness credential cannot mint a socket ticket".into());
    }
    if !TICKET_SOCKETS.contains(&body.socket.as_str()) {
        return refuse(StatusCode::BAD_REQUEST, format!("socket must be one of {TICKET_SOCKETS:?}"));
    }
    let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return refuse(StatusCode::UNAUTHORIZED, "send the access token as Authorization: Bearer".into());
    };
    let Ok(claims) = auth::verify_token(token, &auth::jwt_secret()) else {
        return refuse(StatusCode::UNAUTHORIZED, "not an access token".into());
    };
    let ticket = mint_ws_ticket(claims, &body.socket);
    let mut resp = axum::Json(json!({
        "ticket": ticket,
        "param": "ticket",
        "expires_in": WS_TICKET_TTL.as_secs(),
    }))
    .into_response();
    resp.headers_mut().insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
    resp
}

/// Extract and verify a JWT from WebSocket query params: `/ws/agent` only,
/// where it is a peer token (the console sockets use [`verify_ws_ticket`]).
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

/// How often a socket with a turn in flight sends a `keepalive` frame. The
/// turn's own frames can be minutes apart (a long prefill, a slow tool), and
/// the console gives up on a turn after TURN_IDLE_MS (95 s) with no frame at
/// all, so the keepalive is what tells it the turn is still running.
pub const TURN_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(30);

/// Run one turn to its end, calling `keepalive` every `every` while it runs.
/// `None` when `revoked` resolved first (a logout drops the turn). Generic so
/// the loop is tested with paused time, without a socket.
pub async fn run_turn_with_keepalive<T, K, KF>(
    run: impl std::future::Future<Output = T>,
    revoked: impl std::future::Future<Output = ()>,
    every: std::time::Duration,
    mut keepalive: K,
) -> Option<T>
where
    K: FnMut() -> KF,
    KF: std::future::Future<Output = ()>,
{
    tokio::pin!(run);
    tokio::pin!(revoked);
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    // After a runtime stall, one keepalive, not a burst of them.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // Biased, in this order: a revoke that lands as the turn finishes
        // still wins (a signed-out session gets no reply, P1), and a tick due
        // at the turn's end cannot put a keepalive after its last frame.
        tokio::select! {
            biased;
            _ = &mut revoked => return None,
            r = &mut run => return Some(r),
            _ = tick.tick() => keepalive().await,
        }
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

    /// 0.6.15 console bug: a turn sent no frame between its last token and
    /// `done`, so the console could not tell a slow turn from a lost one.
    #[tokio::test(start_paused = true)]
    async fn a_running_turn_sends_a_keepalive_every_period_and_returns_its_result() {
        let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = n.clone();
        let run = async {
            tokio::time::sleep(std::time::Duration::from_secs(70)).await;
            42
        };
        let got = run_turn_with_keepalive(run, std::future::pending(), TURN_KEEPALIVE, move || {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async {}
        })
        .await;
        assert_eq!(got, Some(42));
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 2, "keepalives at 30 s and 60 s, none before");
    }

    #[tokio::test(start_paused = true)]
    async fn a_revoked_session_drops_the_turn() {
        let run = std::future::pending::<u32>();
        let revoked = tokio::time::sleep(std::time::Duration::from_secs(5));
        assert_eq!(run_turn_with_keepalive(run, revoked, TURN_KEEPALIVE, || async {}).await, None);
    }

    /// Biased: a turn that finishes as the session is revoked delivers nothing.
    #[tokio::test(start_paused = true)]
    async fn a_revoke_ready_with_the_turns_result_wins() {
        let run = std::future::ready(7u32);
        let revoked = std::future::ready(());
        assert_eq!(run_turn_with_keepalive(run, revoked, TURN_KEEPALIVE, || async {}).await, None);
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

#[cfg(test)]
mod ws_ticket_tests {
    use super::*;

    const SECRET: &str = "ws-ticket-test-secret-0123456789abcdef";

    fn claims(exp_in: i64) -> auth::Claims {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        serde_json::from_value(json!({"sub": "alice", "exp": now + exp_in, "role": "user", "scopes": ["read"]})).unwrap()
    }

    fn params(ticket: Option<&str>, token: Option<&str>) -> WsParams {
        WsParams { ticket: ticket.map(str::to_string), token: token.map(str::to_string) }
    }

    /// i515c: a console socket opens with a single-use ticket bound to that
    /// socket; the same ticket never opens a second socket or another path.
    #[test]
    fn a_ticket_opens_one_socket_once() {
        let t = mint_ws_ticket(claims(600), "/ws/coordinator");
        assert!(verify_ws_ticket(&params(Some(&t), None), "/ws/collab", SECRET).is_err(), "bound to its socket");
        let t = mint_ws_ticket(claims(600), "/ws/coordinator");
        assert_eq!(verify_ws_ticket(&params(Some(&t), None), "/ws/coordinator", SECRET).unwrap().sub, "alice");
        assert!(verify_ws_ticket(&params(Some(&t), None), "/ws/coordinator", SECRET).is_err(), "single use");
        let stale = mint_ws_ticket(claims(-1), "/ws/coordinator");
        assert!(verify_ws_ticket(&params(Some(&stale), None), "/ws/coordinator", SECRET).unwrap_err().contains("expired"));
    }

    /// i515c: a JWT in a console socket URL is refused, with the way to do it
    /// instead; there is no fallback to `?token=`.
    #[test]
    fn a_console_socket_refuses_a_token_in_its_url() {
        for socket in TICKET_SOCKETS {
            let e = verify_ws_ticket(&params(None, Some("a.jwt.here")), socket, SECRET).unwrap_err();
            assert!(e.contains("no longer takes ?token=") && e.contains(WS_TICKET_PATH), "{socket}: {e}");
        }
        assert_eq!(verify_ws_ticket(&params(None, None), "/ws/coordinator", SECRET).unwrap_err(), "No ticket provided");
    }

    /// The console's socket handlers authenticate through the ticket, never
    /// through `verify_ws_auth` (the peer socket's JWT-in-URL path).
    #[test]
    fn the_console_handlers_redeem_tickets() {
        for (src, socket) in [(include_str!("ws_coordinator.rs"), "/ws/coordinator"), (include_str!("ws_collab.rs"), "/ws/collab")] {
            let own = crate::test_src::own_code(src);
            let handler = crate::test_src::fn_body(&own, "pub async fn ws_handler(");
            assert!(handler.contains(&format!("verify_ws_ticket(&params, \"{socket}\"")), "{socket}");
            assert!(!handler.contains("verify_ws_auth("), "{socket} must not take a JWT from its URL");
        }
    }
}
