// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! How long an idle client connection may hold a socket in the gateway.
//!
//! On 2026-11-02 the pop-os gateway ran out of file descriptors (RLIMIT_NOFILE
//! 1024) after ~45 h and spent five hours unable to read its secrets or reach
//! Postgres. The sockets were idle HTTP/1 keep-alive connections. A node agent
//! in a retry loop built a fresh Go transport per request (no idle timeout)
//! and left each connection open, about 22 an hour. The gateway never closed
//! them either.
//!
//! hyper's HTTP/1 `header_read_timeout` starts the moment a keep-alive
//! connection goes idle waiting for its next request head, so it is also the
//! idle timeout. But it only runs when the builder has a `Timer`, and
//! axum-server builds hyper's auto builder without one. Every listener the
//! gateway serves calls [`apply`].
//!
//! - HTTP/1: a connection that sends no complete request head for
//!   [`IDLE_SECS`] is closed. A request already being served, or a long
//!   streamed answer, is not affected: the timer runs only while hyper waits
//!   for a head.
//! - HTTP/2: the gateway pings every [`H2_PING_SECS`] and closes a
//!   connection whose peer does not answer within [`H2_PING_TIMEOUT_SECS`],
//!   so a vanished peer does not hold its socket.
//!
//! Old code: no timer, so neither timeout ran; an idle connection was held
//! for the life of the process.

use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder;

/// Idle HTTP/1 keep-alive connections are closed after this long: long
/// enough that a client's next request usually finds its pooled connection
/// still open, and far below the hours a leak needs to matter.
pub const IDLE_SECS: u64 = 60;
pub const H2_PING_SECS: u64 = 30;
pub const H2_PING_TIMEOUT_SECS: u64 = 20;

/// Rehearsal/test-stack knob: the idle bound in whole seconds. Shipped
/// installs never set it.
pub const IDLE_ENV: &str = "NOO_GATEWAY_IDLE_S";

/// The idle bound for a raw `NOO_GATEWAY_IDLE_S` (None = unset), and the
/// reason when the value is unusable. Blank or unusable (non-numeric, zero,
/// negative) keeps [`IDLE_SECS`].
fn idle_secs_from(raw: Option<&str>) -> (u64, Option<&'static str>) {
    match crate::tls::resolve_positive_secs(raw.unwrap_or(""), IDLE_SECS) {
        Ok(secs) => (secs, None),
        Err(why) => (IDLE_SECS, Some(why)),
    }
}

/// The idle bound in force for this process, read once (every listener
/// calls [`apply`]; a bad value is said once).
fn idle_secs() -> u64 {
    static SECS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SECS.get_or_init(|| {
        let raw = std::env::var(IDLE_ENV).ok();
        let (secs, rejected) = idle_secs_from(raw.as_deref());
        match rejected {
            Some(why) => tracing::warn!(
                env = IDLE_ENV, value = %raw.as_deref().unwrap_or(""), %why,
                default_seconds = IDLE_SECS,
                "ignoring an unusable idle connection timeout override; keeping the default"
            ),
            None if secs != IDLE_SECS => {
                tracing::info!(env = IDLE_ENV, seconds = secs, "idle connection timeout overridden");
            }
            None => {}
        }
        secs
    })
}

pub fn apply(b: &mut Builder<TokioExecutor>) {
    apply_with(b, Duration::from_secs(idle_secs()));
}

fn apply_with(b: &mut Builder<TokioExecutor>, idle: Duration) {
    b.http1().timer(TokioTimer::new()).header_read_timeout(idle);
    b.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(H2_PING_SECS))
        .keep_alive_timeout(Duration::from_secs(H2_PING_TIMEOUT_SECS));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn the_idle_bound_is_a_minute_unless_the_rehearsal_sets_it() {
        assert_eq!(IDLE_SECS, 60);
        assert_eq!(idle_secs_from(None), (60, None));
        assert_eq!(idle_secs_from(Some("")), (60, None));
        assert_eq!(idle_secs_from(Some("  ")), (60, None));
        for bad in ["abc", "0", "-5", "1.5"] {
            let (secs, why) = idle_secs_from(Some(bad));
            assert_eq!(secs, 60, "{bad} keeps the default");
            assert!(why.is_some(), "{bad} is said to be unusable");
        }
        assert_eq!(idle_secs_from(Some("10")), (10, None));
        assert_eq!(idle_secs_from(Some(" 15 ")), (15, None));
    }

    /// Serve "ok" on a loopback port; `idle` None = axum-server as it was.
    async fn server(idle: Option<Duration>) -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut s = axum_server::from_tcp(listener).unwrap();
        if let Some(d) = idle {
            apply_with(s.http_builder(), d);
        }
        // A fallback, not a `.route`: the openapi drift check reads every route string.
        let app = axum::Router::new().fallback(|| async { "ok" });
        tokio::spawn(async move { s.serve(app.into_make_service()).await.unwrap() });
        addr
    }

    /// One keep-alive request, then silence: true when the gateway closed
    /// the connection within `wait`.
    async fn closed_after_idle(addr: std::net::SocketAddr, wait: Duration) -> bool {
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: keep-alive\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = c.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"), "{}", String::from_utf8_lossy(&buf[..n]));
        // Read past the response; an EOF (0) inside `wait` is the close.
        loop {
            match tokio::time::timeout(wait, c.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }

    #[tokio::test]
    async fn an_idle_keep_alive_connection_is_closed() {
        let addr = server(Some(Duration::from_millis(300))).await;
        assert!(closed_after_idle(addr, Duration::from_secs(3)).await, "the idle connection was held open");
    }

    /// What the gateway did before: without a timer hyper holds the idle
    /// connection, which is the leak this module exists for.
    #[tokio::test]
    async fn without_the_timer_the_connection_is_held() {
        let addr = server(None).await;
        assert!(!closed_after_idle(addr, Duration::from_millis(1500)).await, "axum-server closed it by itself; recheck this module");
    }
}
