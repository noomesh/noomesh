// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The multiplexer, the handshake checks and the routing, with the node's end
//! played by the test: frames go in through `Session::on_frame` and come out
//! of the session's outbound queue, exactly as `drive` would move them over a
//! WebSocket.

use super::*;
use base64::Engine as _;
use futures::StreamExt;
use reqwest::Method;

// ── helpers ─────────────────────────────────────────────────────────────

/// `host:port` of a node agent, without spelling the port (the guard in
/// tests/test_node_link_is_the_only_node_door.py scans this file too).
fn at(host: &str) -> String {
    format!("{host}:{}", crate::node_link::AGENT_PORT)
}

/// `https://host:port` + `rest`.
fn agent(host: &str, rest: &str) -> String {
    format!("https://{}{rest}", at(host))
}

fn pair(params: SessionParams) -> (Arc<Session>, mpsc::Receiver<Frame>) {
    let (tx, rx) = mpsc::channel(OUT_QUEUE);
    (Session::new("t-node", hub().next_conn_id(), tx, params), rx)
}

fn get(path: &str) -> TunnelRequest {
    TunnelRequest { method: "GET".into(), path: path.into(), headers: vec![], body: TunnelBody::Bytes(vec![]) }
}

async fn next_frame(rx: &mut mpsc::Receiver<Frame>) -> Frame {
    tokio::time::timeout(Duration::from_secs(3), rx.recv()).await.expect("a frame within 3 s").expect("the queue is open")
}

/// Pull frames until one of `kind` for `stream`, returning it and the ones skipped.
async fn frame_of(rx: &mut mpsc::Receiver<Frame>, kind: u8, stream: u32) -> (Frame, Vec<Frame>) {
    let mut skipped = vec![];
    loop {
        let f = next_frame(rx).await;
        if f.kind == kind && f.stream == stream {
            return (f, skipped);
        }
        skipped.push(f);
    }
}

/// The next OPEN, skipping the body-end frames and other traffic before it.
async fn next_open(rx: &mut mpsc::Receiver<Frame>) -> Frame {
    loop {
        let f = next_frame(rx).await;
        if f.kind == FRAME_OPEN {
            return f;
        }
    }
}

/// Everything queued within a short wait.
async fn settle(rx: &mut mpsc::Receiver<Frame>) -> Vec<Frame> {
    tokio::time::sleep(Duration::from_millis(40)).await;
    let mut v = vec![];
    while let Ok(f) = rx.try_recv() {
        v.push(f);
    }
    v
}

fn head(id: u32, status: u16, headers: &[(&str, &str)]) -> Frame {
    Frame::new(FRAME_HEAD, id, json!({"status": status, "headers": headers}).to_string())
}

fn data(id: u32, b: &[u8]) -> Frame {
    Frame::new(FRAME_DATA, id, b.to_vec())
}

fn end(id: u32) -> Frame {
    Frame::new(FRAME_END, id, Bytes::new())
}

async fn collect(resp: TunnelResponse) -> (Vec<u8>, Option<TunnelError>) {
    let mut body = resp.body;
    let mut out = vec![];
    while let Some(item) = body.next().await {
        match item {
            Ok(b) => out.extend_from_slice(&b),
            Err(e) => return (out, Some(e)),
        }
    }
    (out, None)
}

// ── wire pins ───────────────────────────────────────────────────────────

#[test]
fn frames_round_trip_and_short_ones_are_refused() {
    let f = Frame::new(FRAME_DATA, 0x0102_0304, b"abc".to_vec());
    let enc = f.encode();
    assert_eq!(&enc[..], &[3, 1, 2, 3, 4, b'a', b'b', b'c']);
    assert_eq!(Frame::decode(&enc).unwrap(), f);
    assert!(Frame::decode(&[1, 0, 0, 0]).is_err());
    assert_eq!(Frame::decode(&[4, 0, 0, 0, 9]).unwrap(), Frame::new(FRAME_END, 9, Bytes::new()));
}

/// Byte-for-byte the literals in node-agent-go/internal/tunnel
/// (TestCanonicalStringsArePinned).
#[test]
fn the_handshake_canonical_strings_match_the_go_pins() {
    assert_eq!(challenge_canonical("host9", "n0nce", 1_700_000_000), "noo-tunnel-v1\nchallenge\nhost9\nn0nce\n1700000000");
    assert_eq!(hello_canonical("host9", "n0nce", 1_700_000_000), "noo-tunnel-v1\nhello\nhost9\nn0nce\n1700000000");
}

#[test]
fn a_tiny_frame_costs_a_floor_so_it_cannot_outrun_the_window() {
    assert_eq!(cost(0), MIN_COST);
    assert_eq!(cost(1), MIN_COST);
    assert_eq!(cost(MAX_DATA), MAX_DATA);
}

// ── the multiplexer ─────────────────────────────────────────────────────

#[tokio::test]
async fn a_request_goes_out_as_one_open_with_the_principal_and_no_credentials() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    let h = tokio::spawn(async move {
        let req = TunnelRequest {
            method: "POST".into(),
            path: "/v1/chat/completions?stream=1".into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("X-Noo-Backend".into(), "vllm".into()),
                // None of these may cross: credentials a tunnel stream does not
                // need, hop-by-hop, and the reserved principal namespace.
                ("Authorization".into(), "Bearer leaked".into()),
                ("X-Noo-Tunnel-Principal".into(), "controller".into()),
                ("x-noo-tunnel-anything".into(), "1".into()),
                ("Connection".into(), "keep-alive".into()),
                ("Host".into(), "127.0.0.1:1".into()),
            ],
            body: TunnelBody::Bytes(b"{}".to_vec()),
        };
        s2.request(req, None).await
    });
    let open = next_frame(&mut rx).await;
    assert_eq!(open.kind, FRAME_OPEN);
    let v: Value = serde_json::from_slice(&open.payload).unwrap();
    assert_eq!(v["method"], "POST");
    assert_eq!(v["path"], "/v1/chat/completions?stream=1");
    assert_eq!(v["principal"], "controller");
    let names: Vec<String> = v["headers"].as_array().unwrap().iter().map(|h| h[0].as_str().unwrap().to_ascii_lowercase()).collect();
    assert_eq!(names, vec!["content-type", "x-noo-backend"], "only the call's own headers cross");
    let (d, _) = frame_of(&mut rx, FRAME_DATA, open.stream).await;
    assert_eq!(&d.payload[..], b"{}");
    let (e, _) = frame_of(&mut rx, FRAME_END, open.stream).await;
    assert_eq!(e.stream, open.stream);

    sess.on_frame(head(open.stream, 200, &[("content-type", "text/event-stream")]));
    sess.on_frame(data(open.stream, b"data: 1\n\n"));
    sess.on_frame(data(open.stream, b"data: [DONE]\n\n"));
    sess.on_frame(end(open.stream));
    let resp = h.await.unwrap().ok().expect("a response");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.headers, vec![("content-type".to_string(), "text/event-stream".to_string())]);
    let (body, err) = collect(resp).await;
    assert_eq!(body, b"data: 1\n\ndata: [DONE]\n\n");
    assert!(err.is_none());
    assert_eq!(sess.open_streams(), 0, "a finished stream leaves nothing behind");
}

#[tokio::test]
async fn backpressure_a_slow_reader_gets_no_credit_and_a_reader_that_reads_does() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    let h = tokio::spawn(async move { s2.request(get("/big"), None).await });
    let open = next_frame(&mut rx).await;
    let id = open.stream;
    sess.on_frame(head(id, 200, &[]));
    let resp = h.await.unwrap().ok().expect("response");

    // The node fills its whole window; the consumer pulls nothing.
    let chunk = vec![7u8; MAX_DATA];
    for _ in 0..(WINDOW / MAX_DATA) {
        sess.on_frame(data(id, &chunk));
    }
    tokio::task::yield_now().await;
    while let Ok(f) = rx.try_recv() {
        assert_ne!(f.kind, FRAME_CREDIT, "credit is granted when the bytes reach the consumer, not when they arrive");
    }

    // One read gives that chunk's cost back, and only that.
    let mut body = resp.body;
    let first = body.next().await.unwrap().unwrap();
    assert_eq!(first.len(), MAX_DATA);
    let (c, _) = frame_of(&mut rx, FRAME_CREDIT, id).await;
    assert_eq!(&c.payload[..], &(MAX_DATA as u32).to_be_bytes());
    assert!(rx.try_recv().is_err(), "one chunk read, one grant");
    drop(body);
}

#[tokio::test]
async fn a_node_that_overruns_the_stream_window_has_the_stream_reset() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    let h = tokio::spawn(async move { s2.request(get("/x"), None).await });
    let open = next_frame(&mut rx).await;
    let id = open.stream;
    sess.on_frame(head(id, 200, &[]));
    let resp = h.await.unwrap().ok().expect("response");
    // 1-byte frames cost MIN_COST each, so a compliant node sends at most
    // WINDOW / MIN_COST of them before it must wait; 400 is a flood.
    for _ in 0..400 {
        sess.on_frame(data(id, b"x"));
    }
    let (r, _) = frame_of(&mut rx, FRAME_RESET, id).await;
    assert!(String::from_utf8_lossy(&r.payload).contains("window"), "{:?}", r.payload);
    let (_, err) = collect(resp).await;
    assert!(matches!(err, Some(TunnelError::Lost { .. })), "{err:?}");
    assert_eq!(sess.open_streams(), 0);
}

#[tokio::test]
async fn a_request_body_waits_for_the_nodes_credit() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    // 10 chunks of 32 KiB against a 256 KiB window.
    let chunks: Vec<Result<Bytes, std::io::Error>> = (0..10).map(|_| Ok(Bytes::from(vec![1u8; MAX_DATA]))).collect();
    let h = tokio::spawn(async move {
        let req = TunnelRequest { method: "POST".into(), path: "/up".into(), headers: vec![], body: TunnelBody::Stream(futures::stream::iter(chunks).boxed()) };
        s2.request(req, None).await
    });
    let open = next_frame(&mut rx).await;
    let id = open.stream;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut sent = 0;
    while let Ok(f) = rx.try_recv() {
        if f.kind == FRAME_DATA {
            sent += f.payload.len();
        }
        assert_ne!(f.kind, FRAME_END, "the body is not finished");
    }
    assert_eq!(sent, WINDOW, "the sender stops at the window and waits");
    // Grant the rest; the body completes and END follows.
    sess.on_frame(credit_frame(id, 2 * MAX_DATA));
    let mut more = 0;
    loop {
        let f = next_frame(&mut rx).await;
        match f.kind {
            FRAME_DATA => more += f.payload.len(),
            FRAME_END => break,
            _ => {}
        }
    }
    assert_eq!(more, 2 * MAX_DATA);
    sess.on_frame(head(id, 200, &[]));
    sess.on_frame(end(id));
    let resp = h.await.unwrap().ok().expect("response");
    assert_eq!(collect(resp).await.0.len(), 0);
}

#[tokio::test]
async fn the_per_node_stream_cap_answers_busy_and_a_finished_stream_frees_its_place() {
    let params = SessionParams { max_streams: 2, ..SessionParams::default() };
    let (sess, mut rx) = pair(params);
    let mut handles = vec![];
    let mut opens = vec![];
    for p in ["/a", "/b"] {
        let s = sess.clone();
        handles.push(tokio::spawn(async move { s.request(get(p), None).await }));
        opens.push(next_open(&mut rx).await);
    }
    let (o1, o2) = (opens.remove(0), opens.remove(0));
    // Both held open (no head yet): the third is refused at once, and nothing
    // was sent for it.
    let busy = sess.request(get("/c"), None).await.err().expect("over the cap");
    assert!(matches!(busy, TunnelError::Busy { cap: 2, .. }), "{busy:?}");
    assert!(busy.nothing_sent());
    assert!(!settle(&mut rx).await.iter().any(|f| f.kind == FRAME_OPEN), "a refused call opens no stream");
    // Finish the first.
    sess.on_frame(head(o1.stream, 200, &[]));
    sess.on_frame(end(o1.stream));
    let r1 = handles.remove(0).await.unwrap().ok().expect("first response");
    assert!(collect(r1).await.1.is_none());
    // Its place is free again.
    let s = sess.clone();
    let h3 = tokio::spawn(async move { s.request(get("/d"), None).await });
    let o3 = next_open(&mut rx).await;
    sess.on_frame(head(o3.stream, 204, &[]));
    sess.on_frame(end(o3.stream));
    assert_eq!(h3.await.unwrap().ok().expect("third").status, 204);
    drop(o2);
}

#[tokio::test]
async fn a_tunnel_that_drops_mid_stream_ends_the_body_with_a_distinct_error() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    let h = tokio::spawn(async move { s2.request(get("/sse"), None).await });
    let id = next_frame(&mut rx).await.stream;
    sess.on_frame(head(id, 200, &[("content-type", "text/event-stream")]));
    let resp = h.await.unwrap().ok().expect("response");
    sess.on_frame(data(id, b"data: 1\n\n"));
    let mut body = resp.body;
    assert_eq!(&body.next().await.unwrap().unwrap()[..], b"data: 1\n\n");

    let before = crate::node_rpc::counts().get("t-node").map(|c| c.tunnel_aborts).unwrap_or(0);
    sess.close("the connection failed");
    let err = body.next().await.expect("an error item, not a clean end").err().expect("an error");
    match &err {
        TunnelError::Lost { node, reason } => {
            assert_eq!(node, "t-node");
            assert_eq!(reason, "the connection failed");
        }
        other => panic!("expected Lost, got {other:?}"),
    }
    assert!(err.to_string().starts_with("tunnel_lost:"), "{err}");
    assert!(!err.nothing_sent());
    assert!(body.next().await.is_none(), "one error, then the stream is over");
    let after = crate::node_rpc::counts().get("t-node").map(|c| c.tunnel_aborts).unwrap_or(0);
    assert!(after > before, "the abort is counted");
    // And no new stream can be opened on it.
    let e = sess.request(get("/x"), None).await.err().expect("closed");
    assert!(matches!(e, TunnelError::NoTunnel(_)));
}

#[tokio::test]
async fn a_tunnel_that_drops_before_the_response_head_is_lost_not_a_clean_end() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    let h = tokio::spawn(async move { s2.request(get("/x"), None).await });
    let _ = next_frame(&mut rx).await;
    sess.close("dead peer: nothing received inside the keepalive window");
    let e = h.await.unwrap().err().expect("an error");
    assert!(matches!(&e, TunnelError::Lost { reason, .. } if reason.starts_with("dead peer")), "{e:?}");
}

#[tokio::test]
async fn a_caller_that_stops_reading_resets_the_stream_at_the_node() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    let h = tokio::spawn(async move { s2.request(get("/sse"), None).await });
    let id = next_frame(&mut rx).await.stream;
    sess.on_frame(head(id, 200, &[]));
    let resp = h.await.unwrap().ok().expect("response");
    drop(resp);
    let (r, _) = frame_of(&mut rx, FRAME_RESET, id).await;
    assert_eq!(&r.payload[..], b"the caller stopped reading");
    assert_eq!(sess.open_streams(), 0);
    // A stream the node already ended needs no reset.
    let s3 = sess.clone();
    let h = tokio::spawn(async move { s3.request(get("/y"), None).await });
    let id2 = next_frame(&mut rx).await.stream;
    sess.on_frame(head(id2, 200, &[]));
    sess.on_frame(end(id2));
    let resp = h.await.unwrap().ok().expect("response");
    assert!(collect(resp).await.1.is_none());
    assert!(!settle(&mut rx).await.iter().any(|f| f.kind == FRAME_RESET), "no RESET for a stream that ended cleanly");
}

#[tokio::test]
async fn a_node_reset_and_a_deadline_are_their_own_errors() {
    let (sess, mut rx) = pair(SessionParams::default());
    let s2 = sess.clone();
    let h = tokio::spawn(async move { s2.request(get("/x"), None).await });
    let id = next_frame(&mut rx).await.stream;
    sess.on_frame(Frame::new(FRAME_RESET, id, b"stream cap reached on the node".to_vec()));
    let e = h.await.unwrap().err().expect("error");
    assert!(matches!(&e, TunnelError::Reset { reason, .. } if reason.contains("stream cap")), "{e:?}");

    let started = std::time::Instant::now();
    let e = sess.request(get("/slow"), Some(Duration::from_millis(80))).await.err().expect("timeout");
    assert!(matches!(e, TunnelError::Timeout { .. }), "{e:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    // The abandoned stream is reset at the node.
    let (_, _) = frame_of(&mut rx, FRAME_RESET, 2).await;
}

#[tokio::test]
async fn a_bad_path_or_method_is_refused_before_anything_is_sent() {
    let (sess, mut rx) = pair(SessionParams::default());
    for (m, p) in [("GET", "no-slash"), ("GET", "//evil/x"), ("GET", "/a b"), ("GET", "/a\nb"), ("get", "/x"), ("", "/x")] {
        let e = sess
            .request(TunnelRequest { method: m.into(), path: p.into(), headers: vec![], body: TunnelBody::Bytes(vec![]) }, None)
            .await
            .err()
            .expect("refused");
        assert!(matches!(e, TunnelError::BadRequest(_)), "{m} {p}: {e:?}");
    }
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn late_and_unknown_frames_are_ignored_not_fatal() {
    let (sess, _rx) = pair(SessionParams::default());
    sess.on_frame(data(999, b"x"));
    sess.on_frame(end(999));
    sess.on_frame(credit_frame(999, 10));
    sess.on_frame(Frame::new(FRAME_HEAD, 999, b"not json".to_vec()));
    sess.on_frame(Frame::new(77, 1, Bytes::new()));
    assert!(!sess.is_closed());
}

// ── the hub ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_newest_tunnel_for_a_node_wins_and_the_old_one_ending_does_not_evict_it() {
    let hub = Hub::new();
    let (old, _r1) = pair(SessionParams::default());
    let (new, _r2) = pair(SessionParams::default());
    assert!(hub.install(old.clone()).is_none());
    let prev = hub.install(new.clone()).expect("the old session is handed back");
    prev.close("superseded by a newer tunnel from the same node");
    assert!(old.is_closed() && !new.is_closed());
    assert_eq!(hub.live("t-node").map(|s| s.conn_id), Some(new.conn_id));
    // The superseded session finishing must not remove its replacement.
    hub.remove("t-node", old.conn_id);
    assert!(hub.live("t-node").is_some());
    hub.remove("t-node", new.conn_id);
    assert!(hub.live("t-node").is_none());
    // A closed session is not live even before it is removed.
    hub.install(new.clone());
    new.close("x");
    assert!(hub.live("t-node").is_none());
    assert!(hub.live_nodes().is_empty());
}

#[test]
fn hosts_map_to_nodes_case_insensitively() {
    let hub = Hub::new();
    hub.note_host(&at("Host9.TAIL"), "host9");
    assert_eq!(hub.node_for_host(&at("host9.tail")).as_deref(), Some("host9"));
    assert_eq!(hub.node_for_host(&at("other")), None);
}

// ── the keepalive loop ──────────────────────────────────────────────────

/// A transport made of two channels: what `drive` sends lands in `sent`, what
/// the test pushes into `incoming` is what the node "sent".
fn fake_socket() -> (
    impl futures::Sink<Message, Error = std::convert::Infallible> + Unpin,
    mpsc::UnboundedReceiver<Message>,
    mpsc::UnboundedSender<Result<Message, axum::Error>>,
    impl futures::Stream<Item = Result<Message, axum::Error>> + Unpin,
) {
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    let sink = futures::sink::unfold(sent_tx, |tx, m: Message| async move {
        let _ = tx.send(m);
        Ok::<_, std::convert::Infallible>(tx)
    });
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(in_rx);
    (Box::pin(sink), sent_rx, in_tx, stream)
}

#[tokio::test]
async fn drive_pings_on_the_interval_and_drops_a_peer_that_goes_silent() {
    let params = SessionParams { ping_every: Duration::from_millis(30), dead_after: Duration::from_millis(150), ..SessionParams::default() };
    let (sess, out_rx) = pair(params);
    let (sink, mut sent, _keep_open, stream) = fake_socket();
    let s2 = sess.clone();
    let driver = tokio::spawn(async move { drive(s2, sink, stream, out_rx).await });
    // Pings are sent.
    let mut pings = 0;
    while pings < 2 {
        match tokio::time::timeout(Duration::from_secs(2), sent.recv()).await.expect("a message").expect("open") {
            Message::Ping(_) => pings += 1,
            _ => {}
        }
    }
    // The peer never answers: dropped inside dead_after (+ one interval).
    let started = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(3), driver).await.expect("dead peer detected").unwrap();
    assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    assert!(sess.is_closed());
    assert!(sess.reason().starts_with("dead peer"), "{}", sess.reason());
}

#[tokio::test]
async fn drive_keeps_a_peer_that_answers_and_moves_frames_both_ways() {
    let params = SessionParams { ping_every: Duration::from_millis(30), dead_after: Duration::from_millis(150), ..SessionParams::default() };
    let (sess, out_rx) = pair(params);
    let (sink, mut sent, incoming, stream) = fake_socket();
    let s2 = sess.clone();
    let driver = tokio::spawn(async move { drive(s2, sink, stream, out_rx).await });
    // A request goes out as a binary OPEN message.
    let s3 = sess.clone();
    let h = tokio::spawn(async move { s3.request(get("/x"), None).await });
    let open = loop {
        match tokio::time::timeout(Duration::from_secs(2), sent.recv()).await.unwrap().unwrap() {
            Message::Binary(b) => break Frame::decode(&b).unwrap(),
            Message::Ping(_) => {
                let _ = incoming.send(Ok(Message::Pong(Bytes::new())));
            }
            _ => {}
        }
    };
    assert_eq!(open.kind, FRAME_OPEN);
    // The answer arrives as binary messages.
    incoming.send(Ok(Message::Binary(head(open.stream, 200, &[]).encode()))).unwrap();
    incoming.send(Ok(Message::Binary(data(open.stream, b"hi").encode()))).unwrap();
    incoming.send(Ok(Message::Binary(end(open.stream).encode()))).unwrap();
    let resp = h.await.unwrap().ok().expect("response");
    assert_eq!(collect(resp).await.0, b"hi");
    // Keep answering pings for longer than dead_after: still alive.
    let until = tokio::time::Instant::now() + Duration::from_millis(400);
    while tokio::time::Instant::now() < until {
        if let Ok(Some(Message::Ping(_))) = tokio::time::timeout(Duration::from_millis(50), sent.recv()).await {
            let _ = incoming.send(Ok(Message::Pong(Bytes::new())));
        }
    }
    assert!(!sess.is_closed(), "a peer that answers is not dropped");
    // A malformed frame ends the session.
    incoming.send(Ok(Message::Binary(Bytes::from_static(&[1, 2])))).unwrap();
    tokio::time::timeout(Duration::from_secs(2), driver).await.unwrap().unwrap();
    assert!(sess.is_closed());
}

// ── the handshake checks ────────────────────────────────────────────────

struct Leaf {
    key_pem: String,
    cert_pem: String,
    der: Vec<u8>,
}

fn leaf(cn: &str, org: &str) -> Leaf {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.distinguished_name.push(rcgen::DnType::OrganizationName, org);
    let cert = params.self_signed(&key).unwrap();
    Leaf { key_pem: key.serialize_pem(), cert_pem: cert.pem(), der: cert.der().to_vec() }
}

fn hello_for(signer: &Leaf, claims: &str, nonce: &str, ts: i64, presented: &Leaf) -> String {
    let (alg, sig, _) = crate::node_rpc::sign_detached_with_pem(
        hello_canonical(claims, nonce, ts).as_bytes(),
        signer.key_pem.as_bytes(),
        signer.cert_pem.as_bytes(),
    )
    .unwrap();
    json!({
        "t": "hello", "v": 1, "node": claims, "nonce": nonce, "ts": ts, "alg": alg, "sig": sig,
        "cert": base64::engine::general_purpose::STANDARD.encode(&presented.der),
    })
    .to_string()
}

const NONCE: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn a_hello_signed_by_the_nodes_own_leaf_is_accepted() {
    let node = leaf("host9", "Mesh Cluster Node");
    let thumb = crate::node_identity::thumbprint_of(&node.der);
    let now = 1_800_000_000;
    let hello = hello_for(&node, "host9", NONCE, now, &node);
    assert_eq!(verify_hello(&hello, "host9", NONCE, "host9", &thumb, now), Ok(()));
}

#[test]
fn a_node_cannot_open_a_tunnel_as_another_node_id() {
    let host9 = leaf("host9", "Mesh Cluster Node");
    let host3 = leaf("host3", "Mesh Cluster Node");
    let t9 = crate::node_identity::thumbprint_of(&host9.der);
    let now = 1_800_000_000;

    // host9's connection (cert, token) claims to be host3 in the hello.
    let e = verify_hello(&hello_for(&host9, "host3", NONCE, now, &host9), "host9", NONCE, "host9", &t9, now).unwrap_err();
    assert!(e.contains("names node"), "{e}");

    // host9 presents host3's certificate in the hello (it cannot sign with
    // host3's key, but even a valid host3 hello is not this connection's
    // certificate).
    let e = verify_hello(&hello_for(&host3, "host9", NONCE, now, &host3), "host9", NONCE, "host9", &t9, now).unwrap_err();
    assert!(e.contains("other than the one this TLS connection presented"), "{e}");

    // host9's certificate with a signature made by host3's key.
    let forged = hello_for(&host3, "host9", NONCE, now, &host9);
    let e = verify_hello(&forged, "host9", NONCE, "host9", &t9, now).unwrap_err();
    assert!(e.contains("does not verify"), "{e}");

    // The connection's certificate names another node than the token's.
    let t3 = crate::node_identity::thumbprint_of(&host3.der);
    let e = verify_hello(&hello_for(&host3, "host9", NONCE, now, &host3), "host9", NONCE, "host3", &t3, now).unwrap_err();
    assert!(e.contains("certificate names node"), "{e}");

    // A certificate that is not a node's names nobody.
    let svc = leaf("prometheus", "Mesh Cluster Service");
    let ts = crate::node_identity::thumbprint_of(&svc.der);
    let e = verify_hello(&hello_for(&svc, "prometheus", NONCE, now, &svc), "prometheus", NONCE, "prometheus", &ts, now).unwrap_err();
    assert!(e.contains("does not name this node"), "{e}");
}

#[test]
fn a_replayed_stale_or_malformed_hello_is_refused() {
    let node = leaf("host9", "Mesh Cluster Node");
    let thumb = crate::node_identity::thumbprint_of(&node.der);
    let now = 1_800_000_000;
    let hello = hello_for(&node, "host9", NONCE, now, &node);
    // Another connection's challenge.
    let e = verify_hello(&hello, "host9", "ffffffffffffffffffffffffffffffff", "host9", &thumb, now).unwrap_err();
    assert!(e.contains("different challenge"), "{e}");
    // Stale.
    let e = verify_hello(&hello, "host9", NONCE, "host9", &thumb, now + 3600).unwrap_err();
    assert!(e.contains("clock"), "{e}");
    for junk in ["", "{}", "not json", r#"{"t":"hello"}"#] {
        assert!(verify_hello(junk, "host9", NONCE, "host9", &thumb, now).is_err(), "{junk:?}");
    }
    // A hello that is really a challenge.
    let challenge = hello.replace("\"hello\"", "\"challenge\"");
    assert!(verify_hello(&challenge, "host9", NONCE, "host9", &thumb, now).is_err());
}

#[test]
fn admission_needs_the_token_the_certificate_and_they_must_agree() {
    use crate::node_identity::{PeerThumbprint, VerifiedPeer};
    let peer = |n: &str| VerifiedPeer { node: n.to_string() };
    let thumb = PeerThumbprint("tp".into());
    assert_eq!(admit(Some("host9"), Some(&peer("host9")), Some(&thumb)), Ok(("host9".to_string(), "tp".to_string())));
    // A token naming another node than the certificate: a forged node id.
    let (status, why) = admit(Some("host3"), Some(&peer("host9")), Some(&thumb)).unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(why.contains("only as itself"), "{why}");
    // No token actor (a user JWT, an operator key).
    assert!(admit(None, Some(&peer("host9")), Some(&thumb)).unwrap_err().1.contains("for nodes"));
    // No client certificate: names the remedy.
    let (status, why) = admit(Some("host9"), None, None).unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(why.contains("noo cluster provision"), "{why}");
    // A named peer without a thumbprint cannot be bound.
    assert!(admit(Some("host9"), Some(&peer("host9")), None).is_err());
}

#[test]
fn reserved_and_credential_headers_never_cross_in_either_direction() {
    for h in ["Authorization", "authorization", "Host", "Connection", "Transfer-Encoding", "X-Noo-Tunnel-Principal", "x-noo-tunnel", "X-NOO-TUNNEL-Anything"] {
        assert!(drop_request_header(h), "{h}");
    }
    for h in ["content-type", "x-noo-backend", "accept", "content-length", "x-upstream-auth"] {
        assert!(!drop_request_header(h), "{h}");
    }
    for h in ["Connection", "transfer-encoding", "Keep-Alive", "upgrade"] {
        assert!(drop_response_header(h), "{h}");
    }
    assert!(!drop_response_header("content-length"));
    assert!(!drop_response_header("content-type"));
}

// ── routing through NodeLink: tunnel, HTTPS fallback, no unsafe retry ───

/// A fake node: answers every OPEN on `sess` with `reply`.
fn serve_node(sess: Arc<Session>, mut rx: mpsc::Receiver<Frame>, reply: impl Fn(&Value) -> Vec<Frame> + Send + 'static) {
    tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            if f.kind != FRAME_OPEN {
                continue;
            }
            let open: Value = serde_json::from_slice(&f.payload).unwrap();
            for r in reply(&open) {
                let r = Frame { stream: f.stream, ..r };
                if r.kind == 255 {
                    sess.close("the connection failed");
                    break;
                }
                sess.on_frame(r);
                tokio::task::yield_now().await;
            }
        }
    });
}

fn install(node: &str) -> (Arc<Session>, mpsc::Receiver<Frame>) {
    let (tx, rx) = mpsc::channel(OUT_QUEUE);
    let sess = Session::new(node, hub().next_conn_id(), tx, SessionParams::default());
    hub().install(sess.clone());
    (sess, rx)
}

fn tunnelled_link(node: &str, agent_url: &str) -> crate::node_link::NodeLink {
    crate::node_link::NodeLink::from_record(
        node,
        Some(&json!({"agent_url": agent_url, "control_transports": {"https_listener": true, "nats_rpc": false, "tunnel": true}})),
    )
    .unwrap()
}

/// A plain HTTP server standing in for the node's :8081, answering "via-https".
async fn https_stand_in() -> String {
    use axum::routing::any;
    let app = axum::Router::new().fallback(any(|| async { "via-https" }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_call_to_an_advertising_node_with_a_live_tunnel_goes_down_the_tunnel() {
    let node = "route-live";
    let (sess, rx) = install(node);
    serve_node(sess, rx, |open| {
        assert_eq!(open["principal"], "controller");
        vec![head(0, 200, &[("content-type", "text/plain")]), data(0, open["path"].as_str().unwrap().as_bytes()), end(0)]
    });
    let before = crate::node_rpc::counts().get(node).map(|c| c.tunnel).unwrap_or(0);
    // The agent URL is unroutable: reaching it would fail the test.
    let link = tunnelled_link(node, &agent("10.255.255.1", ""));
    let resp = link.request(Method::GET, "/logs/containers-bulk").send().await.expect("answered over the tunnel");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "/logs/containers-bulk");
    let after = crate::node_rpc::counts().get(node).map(|c| c.tunnel).unwrap_or(0);
    assert_eq!(after, before + 1, "counted as a tunnel stream");
}

#[tokio::test]
async fn a_link_that_only_holds_an_address_finds_the_tunnel_by_host() {
    let node = "route-addr";
    let (sess, rx) = install(node);
    serve_node(sess, rx, |open| vec![head(0, 200, &[]), data(0, open["path"].as_str().unwrap().as_bytes()), end(0)]);
    hub().note_host(&at("route-addr.test"), node);
    // for_base is what most call sites build (a record's agent_url in hand).
    let link = crate::node_link::NodeLink::for_base(&agent("route-addr.test", ""));
    let resp = link.request(Method::GET, "/api/containers/web/proxy/index").send().await.expect("answered over the tunnel");
    assert_eq!(resp.text().await.unwrap(), "/api/containers/web/proxy/index");
    assert_eq!(node_for_base(&agent("ROUTE-ADDR.test", "/x")).as_deref(), Some(node));
    // Not once the tunnel is gone.
    hub().live(node).unwrap().close("x");
    assert_eq!(node_for_base(&agent("route-addr.test", "")), None);
}

#[test]
fn a_node_record_answers_to_its_agent_url_and_its_ip() {
    let r = json!({"agent_url": "https://Host9.tail.ts.net:9000", "ip_address": "100.64.0.9"});
    assert_eq!(host_keys(&r), vec!["Host9.tail.ts.net:9000".to_string(), at("100.64.0.9")]);
    assert_eq!(host_keys(&json!({"ip_address": "10.0.0.2"})), vec![at("10.0.0.2")]);
    assert!(host_keys(&json!({"agent_url": "", "ip_address": ""})).is_empty());
    assert!(host_keys(&json!({})).is_empty());
}

#[tokio::test]
async fn without_a_live_tunnel_or_an_advertisement_the_call_is_https_as_before() {
    let url = https_stand_in().await;
    // Advertises, but nothing live: HTTPS.
    let link = tunnelled_link("route-none", &url);
    assert_eq!(link.request(Method::GET, "/x").send().await.unwrap().text().await.unwrap(), "via-https");
    // Live, but the record does not advertise (an old node): HTTPS.
    let (_sess, _rx) = install("route-old");
    let old = crate::node_link::NodeLink::from_record("route-old", Some(&json!({"agent_url": url}))).unwrap();
    assert_eq!(old.request(Method::GET, "/x").send().await.unwrap().text().await.unwrap(), "via-https");
}

#[tokio::test]
async fn a_read_the_tunnel_lost_is_repeated_over_https_once_but_a_write_never_is() {
    let url = https_stand_in().await;
    // The tunnel dies as soon as the call arrives.
    let node = "route-lost";
    let (sess, rx) = install(node);
    serve_node(sess, rx, |_| vec![Frame::new(255, 0, Bytes::new())]);
    let link = tunnelled_link(node, &url);
    let read = link.request(Method::GET, "/logs/some-bulk").send().await.expect("a read falls back");
    assert_eq!(read.text().await.unwrap(), "via-https");

    let node = "route-lost-write";
    let (sess, rx) = install(node);
    serve_node(sess, rx, |_| vec![Frame::new(255, 0, Bytes::new())]);
    let link = tunnelled_link(node, &url);
    let https_before = crate::node_rpc::counts().get(node).map(|c| c.https_other + c.https_control).unwrap_or(0);
    let err = link.request(Method::POST, "/api/containers/start").send().await.err().expect("a write is not retried");
    assert!(err.to_string().contains(node) && err.to_string().contains("tunnel-lost"), "{err}");
    let https_after = crate::node_rpc::counts().get(node).map(|c| c.https_other + c.https_control).unwrap_or(0);
    assert_eq!(https_before, https_after, "the write was not sent over HTTPS");
}

#[tokio::test]
async fn past_the_stream_cap_a_call_is_a_503_not_another_door() {
    let node = "route-busy";
    let (tx, mut rx) = mpsc::channel(OUT_QUEUE);
    let sess = Session::new(node, hub().next_conn_id(), tx, SessionParams { max_streams: 1, ..SessionParams::default() });
    hub().install(sess.clone());
    let link = tunnelled_link(node, &agent("10.255.255.1", ""));
    // Hold the only stream open (no head).
    let l2 = link.clone();
    let held = tokio::spawn(async move { l2.request(Method::GET, "/a").send().await });
    let _ = next_frame(&mut rx).await;
    let resp = link.request(Method::GET, "/b").send().await.expect("a 503 response, not an error");
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "1");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["error"], "tunnel_busy");
    held.abort();
}

// ── a stream through the door: byte-for-byte parity with HTTPS ──────────

fn canned_sse() -> Vec<Bytes> {
    let mut v: Vec<Bytes> = (0..40)
        .map(|i| Bytes::from(format!("data: {{\"id\":\"c1\",\"choices\":[{{\"delta\":{{\"content\":\"tok{}{}\"}}}}]}}\n\n", i, "é".repeat(i % 5))))
        .collect();
    v.push(Bytes::from_static(b"data: [DONE]\n\n"));
    v
}

#[tokio::test]
async fn sse_bytes_are_identical_over_the_tunnel_and_over_https() {
    use axum::routing::post;
    // The reference: the same canned stream from a plain server (what :8081 does).
    let chunks = canned_sse();
    let ref_chunks = chunks.clone();
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let c = ref_chunks.clone();
            async move {
                axum::response::Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(axum::body::Body::from_stream(futures::stream::iter(c.into_iter().map(Ok::<_, std::convert::Infallible>))))
                    .unwrap()
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::new();
    let reference = client.post(format!("http://{addr}/v1/chat/completions")).body("{}").send().await.unwrap();
    let ref_ct = reference.headers().get("content-type").cloned();
    let want = reference.bytes().await.unwrap();

    // The tunnel: a fake node replays the same chunks in awkward slices.
    let node = "sse-par";
    let (sess, rx) = install(node);
    let body = Arc::new(chunks);
    serve_node(sess, rx, move |_| {
        let mut out = vec![head(0, 200, &[("content-type", "text/event-stream")])];
        for c in body.iter() {
            for piece in c.chunks(40) {
                out.push(data(0, piece));
            }
        }
        out.push(end(0));
        out
    });
    hub().note_host(&at("sse-par.test"), node);
    crate::tunnel_door::ensure_started().await;
    let target = crate::tunnel_door::carry(&agent("sse-par.test", "/v1/chat/completions"));
    assert!(target.starts_with("http://127.0.0.1:") && target.ends_with("/sse-par/v1/chat/completions"), "{target}");
    let via = crate::node_link::backend_stream_on(&client, Method::POST, &agent("sse-par.test", "/v1/chat/completions"), "vllm")
        .body("{}")
        .send()
        .await
        .expect("answered through the door");
    assert_eq!(via.headers().get("content-type").cloned(), ref_ct);
    let got = via.bytes().await.unwrap();
    assert_eq!(got, want, "the tunnel must carry the stream byte for byte");
    assert!(got.ends_with(b"data: [DONE]\n\n"));

    // With the tunnel gone the same call is the HTTPS URL, unchanged.
    hub().live(node).unwrap().close("x");
    let plain = agent("sse-par.test", "/v1/chat/completions");
    assert_eq!(crate::tunnel_door::carry(&plain), plain);
}

#[tokio::test]
async fn the_door_refuses_a_request_without_its_secret_and_a_node_without_a_tunnel() {
    crate::tunnel_door::ensure_started().await;
    let door = crate::tunnel_door::door_url("door-ghost", "/health");
    assert!(door.is_none(), "no door URL for a node with no live tunnel");
    // Make a URL with a real secret for a live node, then break the secret.
    let (sess, rx) = install("door-live");
    serve_node(sess, rx, |_| vec![head(0, 200, &[]), data(0, b"ok"), end(0)]);
    let good = crate::tunnel_door::door_url("door-live", "/health").expect("door url");
    let client = reqwest::Client::new();
    assert_eq!(client.get(&good).send().await.unwrap().text().await.unwrap(), "ok");
    let wrong_secret = {
        let (head, tail) = good.split_once("127.0.0.1:").unwrap();
        let (port, rest) = tail.split_once('/').unwrap();
        let (_secret, rest) = rest.split_once('/').unwrap();
        format!("{head}127.0.0.1:{port}/{}/{rest}", "0".repeat(64))
    };
    assert_eq!(client.get(&wrong_secret).send().await.unwrap().status(), 404);
    // A node with no live tunnel behind a good secret is a plain 502.
    let ghost = good.replace("/door-live/", "/door-ghost/");
    let r = client.get(&ghost).send().await.unwrap();
    assert_eq!(r.status(), 502);
    assert_eq!(r.headers().get("x-noo-tunnel-error").unwrap(), "tunnel_unavailable");
}
