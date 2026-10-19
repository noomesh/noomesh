// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The node-held tunnel: the gateway's side of i131 phase 2.
//!
//! A node that has said `control_transports.tunnel` holds an OUTBOUND
//! WebSocket to `GET /api/node/tunnel` on the gateway's own HTTPS listener.
//! The gateway sends the calls that must not wait on an inbound connection to
//! the node's :8081 down it: inference SSE, the container proxy, logs, device
//! blobs. [`crate::node_link`] chooses the tunnel when the node advertises it
//! and one is live, HTTPS :8081 otherwise.
//!
//! # Why our own framing, and no `yamux`
//!
//! A multiplexer crate would add a dependency to a tree that cannot be
//! re-locked from here: `yamux` is not in `Cargo.lock`, and neither side of
//! this wire has a maintained yamux that also gives per-stream credit with a
//! frame-cost floor and a clean WebSocket mapping. WebSocket already gives
//! message boundaries (axum's `ws` feature is on; `tokio-tungstenite` is in
//! the lock), so a frame is one binary message and the multiplexer is a few
//! hundred lines we can test exhaustively. The node side is
//! `node-agent-go/internal/tunnel`; its package comment is the wire spec.
//!
//! # Trust
//!
//! - The upgrade is an ordinary authenticated request: a cluster token whose
//!   actor is a node (`NODE_ROUTES`), on a connection whose mTLS leaf names
//!   the SAME node ([`crate::node_identity::VerifiedPeer`]). A node cannot
//!   open a tunnel as another node id.
//! - Then a challenge/response: the gateway signs `(node, nonce, ts)` with its
//!   leaf (the node verifies the signer is the controller), the node signs
//!   the same nonce with ITS leaf key and the gateway checks the signature
//!   against the certificate the TLS handshake verified. Neither side's
//!   message can be replayed on another connection.
//! - Newest tunnel per node wins; the older one is closed and its streams
//!   aborted.
//! - Every stream is opened by the gateway, stamped `principal: controller`,
//!   and served by the node through its own mux as the controller. A node can
//!   never open a stream toward the gateway, and the principal is never read
//!   from a request header on either side.
//!
//! # Flow control
//!
//! Each direction of each stream has a window of [`WINDOW`] bytes; a DATA
//! frame costs `max(len, MIN_COST)` of it and the receiver grants that cost
//! back (`CREDIT`) once the bytes reach the consumer. A response body a slow
//! reader is not pulling therefore stops the node's handler after one window
//! instead of filling a buffer here. A node holds at most [`MAX_STREAMS`]
//! streams open; the next call is answered 503.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use base64::Engine as _;
use futures::stream::BoxStream;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};

use crate::routes::{AppError, AppResult};
use crate::state::AppState;

// ── protocol constants (mirrored in node-agent-go/internal/tunnel/frame.go) ──

pub const PROTOCOL_VERSION: u32 = 1;
pub const FRAME_OPEN: u8 = 1;
pub const FRAME_HEAD: u8 = 2;
pub const FRAME_DATA: u8 = 3;
pub const FRAME_END: u8 = 4;
pub const FRAME_CREDIT: u8 = 5;
pub const FRAME_RESET: u8 = 6;
/// The largest DATA payload a sender writes.
pub const MAX_DATA: usize = 32 * 1024;
/// The least a DATA frame costs against a window.
pub const MIN_COST: usize = 1024;
/// Per-stream, per-direction window.
pub const WINDOW: usize = 256 * 1024;
/// Concurrent streams per node; the next one is a 503.
pub const MAX_STREAMS: usize = 64;
pub const PING_EVERY: Duration = Duration::from_secs(15);
pub const DEAD_AFTER: Duration = Duration::from_secs(45);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const OUT_QUEUE: usize = 256;
/// Stream ids are u32; a session that has used this many is recycled.
const MAX_STREAM_ID: u32 = 0x7fff_0000;
const CLOCK_SKEW: i64 = 300;

/// What a DATA frame of `n` payload bytes spends from a window.
pub fn cost(n: usize) -> usize {
    n.max(MIN_COST)
}

/// The operator's brake: `NOO_NODE_TUNNEL=0|false|off|no` makes this gateway
/// refuse tunnels (the endpoint answers 404, as an older gateway does) and
/// send every call by the other transports. Default on.
pub fn enabled() -> bool {
    !matches!(
        std::env::var("NOO_NODE_TUNNEL").unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ── frames ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub stream: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(kind: u8, stream: u32, payload: impl Into<Bytes>) -> Self {
        Self { kind, stream, payload: payload.into() }
    }

    pub fn encode(&self) -> Bytes {
        let mut v = Vec::with_capacity(5 + self.payload.len());
        v.push(self.kind);
        v.extend_from_slice(&self.stream.to_be_bytes());
        v.extend_from_slice(&self.payload);
        Bytes::from(v)
    }

    pub fn decode(b: &[u8]) -> Result<Frame, String> {
        if b.len() < 5 {
            return Err(format!("frame of {} bytes is shorter than its 5-byte header", b.len()));
        }
        let stream = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
        Ok(Frame { kind: b[0], stream, payload: Bytes::copy_from_slice(&b[5..]) })
    }
}

fn credit_frame(stream: u32, n: usize) -> Frame {
    Frame::new(FRAME_CREDIT, stream, Bytes::copy_from_slice(&(n.min(u32::MAX as usize) as u32).to_be_bytes()))
}

/// The byte string the gateway signs. Equals the Go `ChallengeCanonical`;
/// both sides pin the same literal.
pub fn challenge_canonical(node: &str, nonce: &str, ts: i64) -> String {
    format!("noo-tunnel-v{PROTOCOL_VERSION}\nchallenge\n{node}\n{nonce}\n{ts}")
}

/// The byte string the node signs. Equals the Go `HelloCanonical`.
pub fn hello_canonical(node: &str, nonce: &str, ts: i64) -> String {
    format!("noo-tunnel-v{PROTOCOL_VERSION}\nhello\n{node}\n{nonce}\n{ts}")
}

// ── errors ──────────────────────────────────────────────────────────────

/// Why a tunnel call failed. `Lost`, `Reset` and `Timeout` are the DISTINCT
/// mid-stream errors: they name the tunnel, never read as an HTTP error from
/// the node, and a caller that sees one knows bytes may have been produced.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TunnelError {
    #[error("no live tunnel to node {0}")]
    NoTunnel(String),
    #[error("node {node} already has {cap} streams open over its tunnel")]
    Busy { node: String, cap: usize },
    #[error("tunnel_lost: the tunnel to node {node} dropped ({reason})")]
    Lost { node: String, reason: String },
    #[error("tunnel_reset: node {node} reset the stream ({reason})")]
    Reset { node: String, reason: String },
    #[error("tunnel_timeout: node {node} sent nothing for {secs}s over its tunnel")]
    Timeout { node: String, secs: u64 },
    #[error("tunnel_request: {0}")]
    BadRequest(String),
}

impl TunnelError {
    /// Nothing reached the node: the call may safely go another way.
    pub fn nothing_sent(&self) -> bool {
        matches!(self, TunnelError::NoTunnel(_) | TunnelError::Busy { .. } | TunnelError::BadRequest(_))
    }
}

// ── requests and responses ──────────────────────────────────────────────

pub enum TunnelBody {
    Bytes(Vec<u8>),
    Stream(BoxStream<'static, Result<Bytes, std::io::Error>>),
}

pub struct TunnelRequest {
    pub method: String,
    /// Path and query, starting with `/`.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: TunnelBody,
}

pub struct TunnelResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: BoxStream<'static, Result<Bytes, TunnelError>>,
}

/// Headers that never cross: they describe a connection that is not the one
/// the node's handler sees, or are credentials a tunnel stream does not need
/// (and a handler should not forward), or are in the reserved namespace.
pub fn drop_request_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "proxy-connection"
            | "te" | "trailer" | "transfer-encoding" | "upgrade" | "host" | "authorization"
    ) || n.starts_with("x-noo-tunnel")
}

/// Response headers a bridge must not copy onto its own connection.
pub fn drop_response_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-connection" | "te" | "trailer"
            | "transfer-encoding" | "upgrade"
    )
}

// ── a session ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct SessionParams {
    pub window: usize,
    pub max_streams: usize,
    pub ping_every: Duration,
    pub dead_after: Duration,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self { window: WINDOW, max_streams: MAX_STREAMS, ping_every: PING_EVERY, dead_after: DEAD_AFTER }
    }
}

enum Event {
    Head { status: u16, headers: Vec<(String, String)> },
    Data(Bytes),
    End,
    /// The node reset the stream.
    Reset(String),
    /// The tunnel went away under the stream.
    Gone(String),
}

struct Slot {
    events: mpsc::Sender<Event>,
    /// The node's credit for our request body.
    credit: Arc<Semaphore>,
    /// Cost of response DATA queued for the consumer and not yet read: the
    /// receive window, enforced in bytes.
    inflight: Arc<AtomicUsize>,
}

/// One live tunnel from one node. Built by [`Session::new`], fed by
/// [`Session::on_frame`], drained by whoever owns the socket (see `drive`).
pub struct Session {
    node: String,
    conn_id: u64,
    out: mpsc::Sender<Frame>,
    streams: Mutex<HashMap<u32, Slot>>,
    next_id: AtomicU32,
    permits: Arc<Semaphore>,
    params: SessionParams,
    closed: AtomicBool,
    shutdown: watch::Sender<bool>,
    last_rx: Mutex<Instant>,
    close_reason: Mutex<String>,
}

impl Session {
    pub fn new(node: &str, conn_id: u64, out: mpsc::Sender<Frame>, params: SessionParams) -> Arc<Self> {
        let (shutdown, _rx) = watch::channel(false);
        Arc::new(Self {
            node: node.to_string(),
            conn_id,
            out,
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            permits: Arc::new(Semaphore::new(params.max_streams)),
            params,
            closed: AtomicBool::new(false),
            shutdown,
            last_rx: Mutex::new(Instant::now()),
            close_reason: Mutex::new(String::new()),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Streams currently open.
    #[cfg(test)]
    pub fn open_streams(&self) -> usize {
        self.streams.lock().map(|m| m.len()).unwrap_or(0)
    }

    fn touch(&self) {
        if let Ok(mut t) = self.last_rx.lock() {
            *t = Instant::now();
        }
    }

    fn idle(&self) -> Duration {
        self.last_rx.lock().map(|t| t.elapsed()).unwrap_or_default()
    }

    fn reason(&self) -> String {
        self.close_reason.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Close the session: every stream is told the tunnel went away (a
    /// distinct error, never a clean end), credit windows are closed and the
    /// socket owner is signalled. Idempotent.
    pub fn close(&self, reason: &str) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut r) = self.close_reason.lock() {
            *r = reason.to_string();
        }
        let slots: Vec<Slot> = match self.streams.lock() {
            Ok(mut m) => m.drain().map(|(_, s)| s).collect(),
            Err(_) => Vec::new(),
        };
        for s in slots {
            s.credit.close();
            let _ = s.events.try_send(Event::Gone(reason.to_string()));
        }
        self.permits.close();
        // `send_replace`, not `send`: the value must stick even when no driver
        // is subscribed yet.
        self.shutdown.send_replace(true);
    }

    fn take_slot(&self, id: u32) -> Option<Slot> {
        let slot = self.streams.lock().ok().and_then(|mut m| m.remove(&id));
        if let Some(s) = &slot {
            s.credit.close();
        }
        slot
    }

    /// Queue a frame without waiting; spawn a task if the queue is full.
    fn send_soon(&self, f: Frame) {
        if let Err(mpsc::error::TrySendError::Full(f)) = self.out.try_send(f) {
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                let out = self.out.clone();
                h.spawn(async move {
                    let _ = out.send(f).await;
                });
            }
        }
    }

    fn reset_soon(&self, id: u32, reason: &str) {
        self.send_soon(Frame::new(FRAME_RESET, id, reason.as_bytes().to_vec()));
    }

    /// A frame arrived from the node.
    pub fn on_frame(&self, f: Frame) {
        match f.kind {
            FRAME_HEAD => {
                #[derive(serde::Deserialize)]
                struct Head {
                    status: u16,
                    #[serde(default)]
                    headers: Vec<(String, String)>,
                }
                match serde_json::from_slice::<Head>(&f.payload) {
                    Ok(h) if (100..1000).contains(&h.status) => {
                        self.deliver(f.stream, Event::Head { status: h.status, headers: h.headers })
                    }
                    _ => self.violation(f.stream, "malformed response head"),
                }
            }
            FRAME_DATA => {
                if f.payload.len() > MAX_DATA {
                    self.violation(f.stream, "DATA frame larger than the maximum");
                    return;
                }
                // The receive window, in bytes: a node that ignores credit
                // cannot make the gateway queue more than one window per stream.
                let inflight = self.streams.lock().ok().and_then(|m| m.get(&f.stream).map(|s| s.inflight.clone()));
                if let Some(inf) = inflight {
                    let c = cost(f.payload.len());
                    if inf.fetch_add(c, Ordering::SeqCst) + c > self.params.window {
                        self.violation(f.stream, "the node sent more than the stream window allows");
                        return;
                    }
                }
                self.deliver(f.stream, Event::Data(f.payload));
            }
            FRAME_END => {
                if let Some(s) = self.take_slot(f.stream) {
                    let _ = s.events.try_send(Event::End);
                }
            }
            FRAME_RESET => {
                if let Some(s) = self.take_slot(f.stream) {
                    let _ = s.events.try_send(Event::Reset(String::from_utf8_lossy(&f.payload).chars().take(200).collect()));
                }
            }
            FRAME_CREDIT => {
                if f.payload.len() == 4 {
                    let n = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) as usize;
                    let credit = self.streams.lock().ok().and_then(|m| m.get(&f.stream).map(|s| s.credit.clone()));
                    if let Some(c) = credit {
                        // A node can only give back what it was sent, so the
                        // credit on a stream never exceeds its window. A grant
                        // past that is a protocol violation, and never reaches
                        // the semaphore (whose add_permits asserts on overflow).
                        if n > self.params.window.saturating_sub(c.available_permits()) {
                            self.violation(f.stream, "credit grant exceeds the stream window");
                        } else {
                            c.add_permits(n);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn deliver(&self, id: u32, ev: Event) {
        let tx = self.streams.lock().ok().and_then(|m| m.get(&id).map(|s| s.events.clone()));
        let Some(tx) = tx else { return }; // late frame for a stream that ended
        if tx.try_send(ev).is_err() {
            self.violation(id, "the node sent more than the stream window allows");
        }
    }

    /// The node broke the protocol on one stream: reset it both ways. The
    /// consumer sees the channel close and reports the tunnel as lost.
    fn violation(&self, id: u32, why: &str) {
        tracing::warn!(node = %self.node, stream = id, why, "tunnel protocol violation; resetting the stream");
        if self.take_slot(id).is_some() {
            self.reset_soon(id, why);
        }
    }

    /// Open a stream, send the request, and wait for the response head. The
    /// returned body streams the rest; dropping it resets the stream.
    pub async fn request(self: &Arc<Self>, req: TunnelRequest, total: Option<Duration>) -> Result<TunnelResponse, TunnelError> {
        self.request_with(req, total, total).await
    }

    /// [`Session::request`] with a separate bound on the wait for the response
    /// head (`head`), for callers that have no total bound of their own.
    pub async fn request_with(
        self: &Arc<Self>,
        req: TunnelRequest,
        total: Option<Duration>,
        head: Option<Duration>,
    ) -> Result<TunnelResponse, TunnelError> {
        if self.is_closed() {
            return Err(TunnelError::NoTunnel(self.node.clone()));
        }
        if !req.path.starts_with('/') || req.path.starts_with("//") || req.path.chars().any(|c| c.is_control() || c == ' ') {
            return Err(TunnelError::BadRequest(format!("path {:?} is not an origin-form path", req.path)));
        }
        if req.method.is_empty() || !req.method.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(TunnelError::BadRequest(format!("method {:?} is not an HTTP method", req.method)));
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| if self.is_closed() { TunnelError::NoTunnel(self.node.clone()) } else { TunnelError::Busy { node: self.node.clone(), cap: self.params.max_streams } })?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        if id >= MAX_STREAM_ID {
            self.close("stream ids exhausted; the node reconnects");
            return Err(TunnelError::NoTunnel(self.node.clone()));
        }
        let (etx, mut erx) = mpsc::channel::<Event>(self.params.window / MIN_COST + 16);
        let credit = Arc::new(Semaphore::new(self.params.window));
        let inflight = Arc::new(AtomicUsize::new(0));
        match self.streams.lock() {
            Ok(mut m) => {
                m.insert(id, Slot { events: etx, credit: credit.clone(), inflight: inflight.clone() });
            }
            Err(_) => return Err(TunnelError::NoTunnel(self.node.clone())),
        }
        let mut guard = StreamGuard { sess: self.clone(), id, _permit: permit, finished: false, pump: None };

        let headers: Vec<(String, String)> =
            req.headers.iter().filter(|(k, _)| !drop_request_header(k)).cloned().collect();
        let open = json!({
            "method": req.method,
            "path": req.path,
            "headers": headers,
            "principal": "controller",
        });
        if self.out.send(Frame::new(FRAME_OPEN, id, open.to_string())).await.is_err() {
            return Err(TunnelError::Lost { node: self.node.clone(), reason: "the tunnel's writer is gone".into() });
        }
        guard.pump = Some(tokio::spawn(pump_body(self.clone(), id, credit, req.body)));

        let now = tokio::time::Instant::now();
        let deadline = total.map(|d| now + d);
        let head_deadline = head.map(|d| now + d);
        let node = self.node.clone();
        let first = recv_by(&mut erx, head_deadline).await;
        let (status, headers) = match first {
            Err(()) => {
                return Err(TunnelError::Timeout { node, secs: head.map(|d| d.as_secs()).unwrap_or(0) });
            }
            Ok(Some(Event::Head { status, headers })) => (status, headers),
            Ok(Some(Event::Reset(why))) => {
                guard.finish();
                return Err(TunnelError::Reset { node, reason: why });
            }
            Ok(Some(Event::Gone(why))) => {
                guard.finish();
                return Err(TunnelError::Lost { node, reason: why });
            }
            Ok(Some(Event::End)) | Ok(Some(Event::Data(_))) => {
                return Err(TunnelError::Lost { node, reason: "the node answered without a response head".into() });
            }
            Ok(None) => {
                guard.finish();
                let why = self.reason();
                return Err(TunnelError::Lost { node, reason: if why.is_empty() { "the tunnel closed before the response".into() } else { why } });
            }
        };
        crate::node_rpc::note_tunnel(&self.node);

        struct St {
            erx: mpsc::Receiver<Event>,
            guard: StreamGuard,
            inflight: Arc<AtomicUsize>,
            node: String,
            deadline: Option<tokio::time::Instant>,
            idle_secs: u64,
            done: bool,
        }
        let st = St { erx, guard, inflight, node: self.node.clone(), deadline, idle_secs: total.map(|d| d.as_secs()).unwrap_or(0), done: false };
        let body = futures::stream::unfold(st, |mut st| async move {
            if st.done {
                return None;
            }
            let ev = recv_by(&mut st.erx, st.deadline).await;
            match ev {
                Err(()) => {
                    st.done = true;
                    crate::node_rpc::note_tunnel_abort(&st.node);
                    let e = TunnelError::Timeout { node: st.node.clone(), secs: st.idle_secs };
                    Some((Err(e), st))
                }
                Ok(Some(Event::Data(b))) => {
                    st.inflight.fetch_sub(cost(b.len()), Ordering::SeqCst);
                    st.guard.grant(b.len());
                    Some((Ok(b), st))
                }
                Ok(Some(Event::End)) => {
                    st.guard.finish();
                    None
                }
                Ok(Some(Event::Reset(why))) => {
                    st.done = true;
                    st.guard.finish();
                    crate::node_rpc::note_tunnel_abort(&st.node);
                    let e = TunnelError::Reset { node: st.node.clone(), reason: why };
                    Some((Err(e), st))
                }
                Ok(Some(Event::Gone(why))) => {
                    st.done = true;
                    st.guard.finish();
                    crate::node_rpc::note_tunnel_abort(&st.node);
                    let e = TunnelError::Lost { node: st.node.clone(), reason: why };
                    Some((Err(e), st))
                }
                Ok(Some(Event::Head { .. })) => {
                    st.done = true;
                    crate::node_rpc::note_tunnel_abort(&st.node);
                    let e = TunnelError::Lost { node: st.node.clone(), reason: "a second response head".into() };
                    Some((Err(e), st))
                }
                Ok(None) => {
                    st.done = true;
                    st.guard.finish();
                    crate::node_rpc::note_tunnel_abort(&st.node);
                    let why = st.guard.sess.reason();
                    let e = TunnelError::Lost {
                        node: st.node.clone(),
                        reason: if why.is_empty() { "the tunnel closed mid-stream".into() } else { why },
                    };
                    Some((Err(e), st))
                }
            }
        })
        .boxed();
        Ok(TunnelResponse { status, headers, body })
    }
}

/// Receive with an optional absolute deadline. `Err(())` is the deadline.
async fn recv_by(rx: &mut mpsc::Receiver<Event>, deadline: Option<tokio::time::Instant>) -> Result<Option<Event>, ()> {
    match deadline {
        Some(d) => tokio::time::timeout_at(d, rx.recv()).await.map_err(|_| ()),
        None => Ok(rx.recv().await),
    }
}

/// Holds a stream's slot, its place under the per-node cap, and its end of
/// the response. Dropping it before the stream ended resets the stream at
/// the node: a caller that stops reading must not leave a handler writing.
struct StreamGuard {
    sess: Arc<Session>,
    id: u32,
    _permit: OwnedSemaphorePermit,
    finished: bool,
    /// The task uploading the request body; aborted with the stream.
    pump: Option<tokio::task::JoinHandle<()>>,
}

impl StreamGuard {
    fn finish(&mut self) {
        self.finished = true;
    }

    /// The consumer took `n` bytes: give the node that much window back.
    fn grant(&self, n: usize) {
        self.sess.send_soon(credit_frame(self.id, cost(n)));
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if let Some(h) = self.pump.take() {
            h.abort();
        }
        // A stream the node already ended (END/RESET) has no slot left and
        // needs no reset.
        let had_slot = self.sess.take_slot(self.id).is_some();
        if !self.finished && had_slot {
            self.sess.reset_soon(self.id, "the caller stopped reading");
        }
    }
}

async fn pump_body(sess: Arc<Session>, id: u32, credit: Arc<Semaphore>, body: TunnelBody) {
    let ok = match body {
        TunnelBody::Bytes(v) => send_chunks(&sess, id, &credit, &v).await,
        TunnelBody::Stream(mut s) => loop {
            match s.next().await {
                None => break true,
                Some(Ok(b)) => {
                    if !send_chunks(&sess, id, &credit, &b).await {
                        break false;
                    }
                }
                Some(Err(e)) => {
                    sess.reset_soon(id, &format!("the request body failed: {e}"));
                    break false;
                }
            }
        },
    };
    if ok {
        let _ = sess.out.send(Frame::new(FRAME_END, id, Bytes::new())).await;
    }
}

async fn send_chunks(sess: &Arc<Session>, id: u32, credit: &Arc<Semaphore>, data: &[u8]) -> bool {
    for chunk in data.chunks(MAX_DATA) {
        match credit.acquire_many(cost(chunk.len()) as u32).await {
            Ok(p) => p.forget(),
            Err(_) => return false,
        }
        if sess.out.send(Frame::new(FRAME_DATA, id, Bytes::copy_from_slice(chunk))).await.is_err() {
            return false;
        }
    }
    true
}

/// A tunnel response as the `reqwest::Response` an HTTPS call would have
/// produced: status and headers as the node sent them, the body streamed. A
/// tunnel that drops mid-body surfaces as a body error whose source chain
/// carries `tunnel_lost: ...` (see [`TunnelError`]).
pub fn into_reqwest(resp: TunnelResponse) -> reqwest::Response {
    let mut b = axum::http::Response::builder().status(resp.status);
    if let Some(h) = b.headers_mut() {
        for (k, v) in &resp.headers {
            if drop_response_header(k) {
                continue;
            }
            if let (Ok(name), Ok(val)) = (axum::http::HeaderName::from_bytes(k.as_bytes()), axum::http::HeaderValue::from_str(v)) {
                h.append(name, val);
            }
        }
    }
    let body = reqwest::Body::wrap_stream(resp.body);
    match b.body(body) {
        Ok(r) => reqwest::Response::from(r),
        Err(_) => reqwest::Response::from(
            axum::http::Response::builder().status(502).body(reqwest::Body::from(Vec::<u8>::new())).expect("static response"),
        ),
    }
}

/// The 503 a call gets when its node already has [`MAX_STREAMS`] streams open.
pub fn busy_response(e: &TunnelError) -> reqwest::Response {
    let body = json!({"detail": e.to_string(), "error": "tunnel_busy"}).to_string();
    let r = axum::http::Response::builder()
        .status(503)
        .header("content-type", "application/json")
        .header("retry-after", "1")
        .body(reqwest::Body::from(body))
        .expect("static response");
    reqwest::Response::from(r)
}

// ── the hub: which nodes have a live tunnel ─────────────────────────────

pub struct Hub {
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    /// `host:port` of a node's agent URL -> node id, so a call that only
    /// holds a backend URL can find the tunnel. Kept after a tunnel drops, so
    /// the HTTPS fallback is still attributed to the node.
    hosts: RwLock<HashMap<String, String>>,
    seq: AtomicU64,
}

impl Hub {
    pub fn new() -> Self {
        Self { sessions: RwLock::new(HashMap::new()), hosts: RwLock::new(HashMap::new()), seq: AtomicU64::new(1) }
    }

    pub fn next_conn_id(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// The node's live session, if it has one.
    pub fn live(&self, node: &str) -> Option<Arc<Session>> {
        self.sessions.read().ok().and_then(|m| m.get(node).cloned()).filter(|s| !s.is_closed())
    }

    /// Make `s` the node's session. The previous one is returned for the
    /// caller to close: newest tunnel wins.
    pub fn install(&self, s: Arc<Session>) -> Option<Arc<Session>> {
        self.sessions.write().ok().and_then(|mut m| m.insert(s.node.clone(), s))
    }

    /// Forget a session, but only if it is still the node's current one (a
    /// superseded session ending must not evict its replacement).
    pub fn remove(&self, node: &str, conn_id: u64) {
        if let Ok(mut m) = self.sessions.write() {
            if m.get(node).map(|s| s.conn_id) == Some(conn_id) {
                m.remove(node);
            }
        }
    }

    /// Record that `hostport` is the address `node`'s tunnel was observed
    /// coming from. Refused (the other node's id is returned) when another
    /// node with a live tunnel already holds it; the node's own earlier
    /// addresses are dropped first. Only the gateway's own observation of the
    /// connection may be passed here, never an address a node reports.
    pub fn claim_host(&self, hostport: &str, node: &str) -> Result<(), String> {
        let key = hostport.to_ascii_lowercase();
        let Ok(mut h) = self.hosts.write() else { return Err(String::new()) };
        if let Some(owner) = h.get(&key) {
            if owner != node && self.live(owner).is_some() {
                return Err(owner.clone());
            }
        }
        h.retain(|_, v| v != node);
        h.insert(key, node.to_string());
        Ok(())
    }

    pub fn node_for_host(&self, hostport: &str) -> Option<String> {
        self.hosts.read().ok().and_then(|h| h.get(&hostport.to_ascii_lowercase()).cloned())
    }

    /// Nodes with a live tunnel (for tests and diagnostics).
    #[cfg(test)]
    pub fn live_nodes(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .sessions
            .read()
            .map(|m| m.iter().filter(|(_, s)| !s.is_closed()).map(|(k, _)| k.clone()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

static HUB: OnceLock<Hub> = OnceLock::new();

/// This process's hub.
pub fn hub() -> &'static Hub {
    HUB.get_or_init(Hub::new)
}

// ── the handshake ───────────────────────────────────────────────────────

/// Verify an ECDSA signature the way the node made it: ASN.1 DER over `msg`,
/// by the key in `cert_der`, under `alg` (`ES256` / `ES384`). The provider's
/// own verification algorithms are used, so nothing new is trusted.
fn verify_ecdsa(cert_der: &[u8], alg: &str, msg: &[u8], sig_der: &[u8]) -> Result<(), String> {
    use x509_parser::prelude::FromDer;
    let scheme = match alg {
        "ES256" => rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        "ES384" => rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        other => return Err(format!("unsupported signature algorithm {other:?}")),
    };
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der).map_err(|_| "the hello's certificate does not parse".to_string())?;
    let spk = &cert.public_key().subject_public_key.data[..];
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algs = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(s, _)| *s == scheme)
        .map(|(_, a)| *a)
        .ok_or_else(|| "this build cannot verify that signature algorithm".to_string())?;
    if algs.iter().any(|a| a.verify_signature(spk, msg, sig_der).is_ok()) {
        Ok(())
    } else {
        Err("the hello's signature does not verify against the node's certificate".into())
    }
}

/// Check the node's hello against everything the connection already proved.
/// `peer_node` and `peer_thumbprint` come from the TLS handshake (the
/// verified client certificate); `expected_node` is the node the upgrade
/// request's token named; `nonce` is the one this connection was challenged
/// with. Every mismatch is a refusal that names it.
pub fn verify_hello(
    text: &str,
    expected_node: &str,
    nonce: &str,
    peer_node: &str,
    peer_thumbprint: &str,
    now: i64,
) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    struct Hello {
        t: String,
        v: u32,
        node: String,
        nonce: String,
        ts: i64,
        alg: String,
        sig: String,
        cert: String,
    }
    let h: Hello = serde_json::from_str(text).map_err(|_| "the hello is not understood".to_string())?;
    if h.t != "hello" || h.v != PROTOCOL_VERSION {
        return Err("the first message was not a v1 hello".into());
    }
    if h.node != expected_node {
        return Err(format!("the hello names node {:?} but the connection is node {:?}", h.node, expected_node));
    }
    if peer_node != expected_node {
        return Err(format!("the client certificate names node {peer_node:?}, not {expected_node:?}"));
    }
    if h.nonce != nonce {
        return Err("the hello answers a different challenge".into());
    }
    if (h.ts - now).abs() > CLOCK_SKEW {
        return Err(format!("the hello is {}s from this gateway's clock (check NTP on both ends)", h.ts - now));
    }
    let der = base64::engine::general_purpose::STANDARD.decode(&h.cert).map_err(|_| "the hello's certificate is not base64".to_string())?;
    if der.is_empty() || der.len() > 16 << 10 {
        return Err("the hello's certificate has a bad size".into());
    }
    if crate::node_identity::thumbprint_of(&der) != peer_thumbprint {
        return Err("the hello is signed with a certificate other than the one this TLS connection presented".into());
    }
    match crate::node_identity::identity_from_cert(&der) {
        Some(p) if p.node == expected_node => {}
        _ => return Err("the hello's certificate does not name this node".into()),
    }
    let sig = base64::engine::general_purpose::STANDARD.decode(&h.sig).map_err(|_| "the hello's signature is not base64".to_string())?;
    verify_ecdsa(&der, &h.alg, hello_canonical(expected_node, nonce, h.ts).as_bytes(), &sig)
}

async fn handshake(socket: &mut WebSocket, node: &str, peer_thumbprint: &str) -> Result<(), String> {
    let nonce = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let ts = now_unix();
    let (alg, sig, cert) = crate::node_rpc::sign_detached(challenge_canonical(node, &nonce, ts).as_bytes())
        .map_err(|e| format!("the gateway cannot sign the tunnel challenge: {e}"))?;
    let challenge = json!({"t": "challenge", "v": PROTOCOL_VERSION, "node": node, "nonce": nonce, "ts": ts, "alg": alg, "sig": sig, "cert": cert});
    socket
        .send(Message::Text(challenge.to_string().into()))
        .await
        .map_err(|e| format!("could not send the challenge: {e}"))?;
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv())
        .await
        .map_err(|_| "the node did not answer the challenge in time".to_string())?
        .ok_or_else(|| "the node closed during the handshake".to_string())?
        .map_err(|e| format!("handshake read failed: {e}"))?;
    let Message::Text(text) = msg else {
        return Err("the node's answer to the challenge was not a text message".into());
    };
    // The TLS handshake proved the certificate; the cluster token proved the
    // actor; both were checked before the upgrade (see `upgrade`). Here the
    // node proves it holds the key.
    verify_hello(text.as_str(), node, &nonce, node, peer_thumbprint, now_unix())
}

// ── routes ──────────────────────────────────────────────────────────────

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/node/tunnel", get(upgrade))
        // "streaming over tunnel" verify row: one stream round trip.
        .route("/api/cluster/nodes/{node_id}/tunnel-probe", get(tunnel_probe))
}

fn refuse(status: StatusCode, detail: &str) -> Response {
    (status, Json(json!({"detail": detail}))).into_response()
}

/// Who may open a tunnel, as a pure decision: `(node, certificate
/// thumbprint)` when the token's actor, the TLS client certificate and the
/// certificate's thumbprint are all present and agree; else the refusal, with
/// the remedy in its text.
pub(crate) fn admit(
    actor: Option<&str>,
    peer: Option<&crate::node_identity::VerifiedPeer>,
    thumb: Option<&crate::node_identity::PeerThumbprint>,
) -> Result<(String, String), (StatusCode, &'static str)> {
    let Some(actor) = actor else {
        return Err((StatusCode::FORBIDDEN, "the node tunnel is for nodes: authenticate with the node's cluster token"));
    };
    let Some(peer) = peer else {
        return Err((
            StatusCode::FORBIDDEN,
            "the node tunnel needs the node's mTLS client certificate; re-run `noo cluster provision <node>` so the agent holds its leaf",
        ));
    };
    if peer.node != actor {
        return Err((
            StatusCode::FORBIDDEN,
            "a node can open a tunnel only as itself: the token names a different node than the client certificate",
        ));
    }
    let Some(thumb) = thumb else {
        return Err((StatusCode::FORBIDDEN, "the node tunnel needs the node's mTLS client certificate"));
    };
    Ok((peer.node.clone(), thumb.0.clone()))
}

/// GET /api/node/tunnel: the node's upgrade. Admission: a node-actor cluster
/// token (the auth layer put it in `ClusterNode`), on a connection whose mTLS
/// leaf names the same node, with a certificate thumbprint to bind the hello
/// to. Anything less is refused with the remedy. After the upgrade the node
/// must still answer the gateway's signed challenge.
async fn upgrade(
    caller: Option<Extension<crate::auth::ClusterNode>>,
    peer: Option<Extension<Option<crate::node_identity::VerifiedPeer>>>,
    thumb: Option<Extension<Option<crate::node_identity::PeerThumbprint>>>,
    axum::extract::ConnectInfo(remote): axum::extract::ConnectInfo<std::net::SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    if !enabled() {
        return refuse(StatusCode::NOT_FOUND, "node tunnels are switched off on this gateway (NOO_NODE_TUNNEL)");
    }
    let actor = caller.map(|Extension(crate::auth::ClusterNode(actor, _))| actor);
    let peer = peer.and_then(|Extension(p)| p);
    let thumb = thumb.and_then(|Extension(t)| t);
    let (node, thumbprint) = match admit(actor.as_deref(), peer.as_ref(), thumb.as_ref()) {
        Ok(x) => x,
        Err((status, why)) => {
            tracing::warn!(actor = ?actor, peer = ?peer.as_ref().map(|p| p.node.as_str()), why, "node tunnel refused");
            return refuse(status, why);
        }
    };
    // Limits before anything is buffered: the frame as well as the message.
    ws.max_frame_size(MAX_DATA + 64 * 1024)
        .max_message_size(MAX_DATA + 64 * 1024)
        .on_upgrade(move |socket| run_socket(socket, node, thumbprint, remote.ip()))
}

async fn run_socket(mut socket: WebSocket, node: String, thumbprint: String, peer_ip: std::net::IpAddr) {
    if let Err(e) = handshake(&mut socket, &node, &thumbprint).await {
        tracing::warn!(node = %node, error = %e, "node tunnel handshake refused");
        let refused = json!({"t": "refused", "reason": e});
        let _ = socket.send(Message::Text(refused.to_string().into())).await;
        let _ = socket.close().await;
        return;
    }
    let params = SessionParams::default();
    let ready = json!({"t": "ready", "v": PROTOCOL_VERSION, "window": params.window, "max_streams": params.max_streams});
    if socket.send(Message::Text(ready.to_string().into())).await.is_err() {
        return;
    }
    // The loopback door lets callers that hold only a reqwest builder reach
    // this session; it starts with the first tunnel.
    crate::tunnel_door::ensure_started().await;
    claim_peer_address(&node, peer_ip);

    let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
    let sess = Session::new(&node, hub().next_conn_id(), out_tx, params);
    if let Some(prev) = hub().install(sess.clone()) {
        tracing::info!(node = %node, "newer node tunnel supersedes the previous one");
        prev.close("superseded by a newer tunnel from the same node");
    }
    tracing::info!(node = %node, "node tunnel up");
    let (sink, stream) = socket.split();
    drive(sess.clone(), sink, stream, out_rx).await;
    sess.close("the connection ended");
    hub().remove(&node, sess.conn_id);
    tracing::info!(node = %node, reason = %sess.reason(), "node tunnel down");
}

/// The `host:port` key for an observed peer address.
pub(crate) fn peer_key(ip: std::net::IpAddr) -> String {
    let ip = ip.to_canonical();
    match ip {
        std::net::IpAddr::V4(v4) => format!("{v4}:{}", crate::node_link::AGENT_PORT),
        std::net::IpAddr::V6(v6) => format!("[{v6}]:{}", crate::node_link::AGENT_PORT),
    }
}

/// Let a caller that holds only an address find this node's tunnel, keyed by
/// the address the gateway SAW the tunnel connect from: never by an
/// `agent_url` or `ip_address` the node reports, which any node could set to
/// another node's address to receive that node's traffic. An address another
/// live node already holds is not shared; calls to it stay on HTTPS.
fn claim_peer_address(node: &str, ip: std::net::IpAddr) {
    let key = peer_key(ip);
    if let Err(owner) = hub().claim_host(&key, node) {
        tracing::warn!(node = %node, address = %key, held_by = %owner,
            "node tunnel: this address is already held by another node's live tunnel; calls to it by address stay on HTTPS");
    }
}

/// The node with a LIVE tunnel whose agent is `base` (`https://host:port`).
pub fn node_for_base(base: &str) -> Option<String> {
    let u = reqwest::Url::parse(base).ok()?;
    let key = format!("{}:{}", u.host_str()?.to_ascii_lowercase(), u.port_or_known_default()?);
    let node = hub().node_for_host(&key)?;
    hub().live(&node).map(|_| node)
}

/// Resolves when the session is closed. The `watch` guard lives and dies
/// inside this function so no non-`Send` guard is held across the caller's
/// `select!`.
async fn closed(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|c| *c).await;
}

/// Pump one session until it ends: frames in from the node, frames out to it,
/// pings every [`PING_EVERY`], and a dead peer (nothing, not even a pong, for
/// [`DEAD_AFTER`]) dropped. Every send is bounded so a peer that stops
/// reading cannot stall the pings that would notice it.
pub(crate) async fn drive<S, R>(sess: Arc<Session>, mut sink: S, mut stream: R, mut out_rx: mpsc::Receiver<Frame>)
where
    S: futures::Sink<Message> + Unpin,
    R: futures::Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    let mut ping = tokio::time::interval(sess.params.ping_every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown = sess.shutdown.subscribe();
    let send_bound = sess.params.dead_after;
    let reason: &str = loop {
        tokio::select! {
            biased;
            _ = closed(&mut shutdown) => break "the session was closed",
            msg = stream.next() => match msg {
                None => break "the node closed the connection",
                Some(Err(_)) => break "the connection failed",
                Some(Ok(m)) => {
                    sess.touch();
                    match m {
                        Message::Binary(b) => match Frame::decode(&b) {
                            Ok(f) => sess.on_frame(f),
                            Err(_) => break "the node sent a malformed frame",
                        },
                        Message::Close(_) => break "the node closed the connection",
                        Message::Ping(p) => {
                            if !matches!(tokio::time::timeout(send_bound, sink.send(Message::Pong(p))).await, Ok(Ok(()))) {
                                break "the node stopped reading";
                            }
                        }
                        _ => {}
                    }
                }
            },
            f = out_rx.recv() => match f {
                None => break "the session's writer closed",
                Some(f) => {
                    if !matches!(tokio::time::timeout(send_bound, sink.send(Message::Binary(f.encode()))).await, Ok(Ok(()))) {
                        break "the node stopped reading";
                    }
                }
            },
            _ = ping.tick() => {
                if sess.idle() > sess.params.dead_after {
                    break "dead peer: nothing received inside the keepalive window";
                }
                if !matches!(tokio::time::timeout(send_bound, sink.send(Message::Ping(Bytes::new()))).await, Ok(Ok(()))) {
                    break "the node stopped reading";
                }
            }
        }
    };
    sess.close(reason);
}

// ── probe ───────────────────────────────────────────────────────────────

/// GET /api/cluster/nodes/{node_id}/tunnel-probe
///
/// One stream round trip over the node's tunnel, for `noo cluster verify`'s
/// "streaming over tunnel" row. Never falls back to HTTPS: the point is to
/// learn whether the TUNNEL works. A node that does not advertise a tunnel
/// answers `checked: false` (the row reads NOT CHECKED, never ok).
async fn tunnel_probe(
    State(state): State<Arc<AppState>>,
    caller: Option<Extension<crate::auth::ClusterNode>>,
    requester: Option<Extension<crate::auth::RequesterCtx>>,
    Path(node_id): Path<String>,
) -> AppResult {
    crate::routes::operator_read_guard(&requester)?;
    if caller.is_some() {
        return Err(AppError::Forbidden("a node may not probe the controller's control paths".into()));
    }
    let link = crate::node_link::NodeLink::for_node(&state, &node_id).await?;
    Ok(Json(link.probe_tunnel().await))
}

#[cfg(test)]
mod tests;
