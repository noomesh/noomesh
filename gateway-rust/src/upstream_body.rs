// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Reading the body of an upstream's 2xx answer (i460).
//!
//! A 2xx status says the upstream accepted the call; it does not say the
//! answer arrived. Read with `resp.json().await.unwrap_or(json!({}))`, a body
//! cut off mid-transfer or one that is not JSON became an empty success: a
//! sandbox run read as "(no output)", a node's MCP tool as an empty result
//! recorded `ok = true`, a node's tool list as "this node has no tools",
//! Ollama's create as an invented `{"status": "success"}`. An agent acted on
//! each of those as if it were the upstream's answer.
//!
//! [`json_2xx`] and [`text_2xx`] read the body and turn either failure into
//! an error that names the upstream and the status, so the caller reports
//! it the way it reports any other failed call. Error branches (non-2xx)
//! may still read leniently: there the body only decorates a failure the
//! status already reported.

use serde_json::Value;

/// The 2xx body as JSON. A body that cannot be read in full, or is not
/// JSON, is an error naming `upstream` and the status.
pub async fn json_2xx(resp: reqwest::Response, upstream: &str) -> Result<Value, String> {
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.map_err(|e| unread(upstream, status, &e))?;
    serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "{upstream} answered HTTP {status} but its body is not JSON ({e}): {}",
            snippet(&String::from_utf8_lossy(&bytes))
        )
    })
}

/// The 2xx body as text. A body that cannot be read in full is an error
/// naming `upstream` and the status, never an empty string.
pub async fn text_2xx(resp: reqwest::Response, upstream: &str) -> Result<String, String> {
    let status = resp.status().as_u16();
    resp.text().await.map_err(|e| unread(upstream, status, &e))
}

/// The upstream's status and its whole body, for a route that passes both
/// through. A body that cannot be read in full is an error naming
/// `upstream` and the status: passed through, it would be the upstream's
/// status over a partial or empty body (an interrupted 200 read as an empty
/// success).
pub async fn whole_text(resp: reqwest::Response, upstream: &str) -> Result<(u16, String), String> {
    let status = resp.status().as_u16();
    resp.text().await.map(|b| (status, b)).map_err(|e| unread(upstream, status, &e))
}

/// reqwest's Display for a body error is "error decoding response body";
/// the cause ("end of file before message length reached") is in the chain.
fn unread(upstream: &str, status: u16, e: &reqwest::Error) -> String {
    let mut msg = format!("{upstream} answered HTTP {status} but its body could not be read: {e}");
    let mut src = std::error::Error::source(e);
    while let Some(inner) = src {
        msg.push_str(": ");
        msg.push_str(&inner.to_string());
        src = inner.source();
    }
    msg
}

fn snippet(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() <= 200 {
        return t.to_string();
    }
    let cut: String = t.chars().take(200).collect();
    format!("{cut}…")
}

/// A loopback HTTP/1.1 server for tests: every connection gets the status
/// line, a `content-length` (`None` = the body's own), then `body`, and the
/// socket closes. A `content-length` larger than `body` is a transfer cut
/// short. Returns `http://127.0.0.1:<port>`.
#[cfg(test)]
pub(crate) async fn stub(status_line: &'static str, content_length: Option<usize>, body: &'static [u8]) -> String {
    let content_length = content_length.unwrap_or(body.len());
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {content_length}\r\nconnection: close\r\n\r\n"
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// A 200 whose body stops short of its `content-length`.
#[cfg(test)]
pub(crate) async fn stub_cut_short() -> String {
    stub("200 OK", Some(64), b"{\"output\":\"").await
}

/// A 200 whose whole body arrives and is not JSON.
#[cfg(test)]
pub(crate) async fn stub_not_json() -> String {
    stub("200 OK", None, b"<html>proxy page</html>").await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(base: &str) -> reqwest::Response {
        reqwest::Client::builder().build().unwrap().get(format!("{base}/x")).send().await.unwrap()
    }

    #[tokio::test]
    async fn a_whole_json_body_reads() {
        let base = stub("200 OK", None, b"{\"ok\":true}").await;
        assert_eq!(json_2xx(get(&base).await, "the node").await.unwrap(), serde_json::json!({"ok": true}));
        let base = stub("200 OK", None, b"hello").await;
        assert_eq!(text_2xx(get(&base).await, "the node").await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn a_body_cut_short_is_an_error_naming_the_upstream_and_status() {
        let base = stub_cut_short().await;
        let e = json_2xx(get(&base).await, "the sandbox").await.unwrap_err();
        assert!(e.starts_with("the sandbox answered HTTP 200 but its body could not be read"), "{e}");
        let base = stub_cut_short().await;
        let e = text_2xx(get(&base).await, "the sandbox").await.unwrap_err();
        assert!(e.starts_with("the sandbox answered HTTP 200 but its body could not be read"), "{e}");
    }

    /// A pass-through keeps the upstream's status and body, whatever the
    /// status; only a body cut short is an error, and it names the status.
    #[tokio::test]
    async fn a_pass_through_keeps_status_and_body_and_refuses_a_cut_body() {
        let base = stub("404 Not Found", None, b"no such stream").await;
        assert_eq!(whole_text(get(&base).await, "Loki").await.unwrap(), (404, "no such stream".to_string()));
        let base = stub_not_json().await;
        assert_eq!(whole_text(get(&base).await, "Loki").await.unwrap().1, "<html>proxy page</html>", "not JSON is not this helper's business");
        let base = stub_cut_short().await;
        let e = whole_text(get(&base).await, "Loki").await.unwrap_err();
        assert!(e.starts_with("Loki answered HTTP 200 but its body could not be read"), "{e}");
    }

    /// The four pass-through and read sites of i460 part 2 read through this
    /// module; none reads its body with a default.
    #[test]
    fn the_pass_through_sites_read_whole_bodies() {
        for (file, src, marker) in [
            ("addon_proxy.rs", include_str!("addon_proxy.rs"), "async fn forward("),
            ("routes/admin.rs", include_str!("routes/admin.rs"), "async fn logs_query("),
            ("routes/inference.rs", include_str!("routes/inference.rs"), "async fn proxy_backend_health("),
            ("routes/cluster.rs", include_str!("routes/cluster.rs"), "async fn cluster_gpu_metrics("),
        ] {
            let own = crate::test_src::own_code(src);
            let body = crate::test_src::fn_body(&own, marker);
            assert!(body.contains("crate::upstream_body::"), "{file} {marker} does not read through upstream_body");
            let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(!compact.contains(".text().await.unwrap_or"), "{file} {marker} reads a body with a default");
        }
    }

    #[tokio::test]
    async fn a_body_that_is_not_json_is_an_error_showing_what_came() {
        let base = stub_not_json().await;
        let e = json_2xx(get(&base).await, "Ollama").await.unwrap_err();
        assert!(e.starts_with("Ollama answered HTTP 200 but its body is not JSON"), "{e}");
        assert!(e.contains("<html>proxy page</html>"), "{e}");
    }

    /// The guard (i460): inside a `… is_success() => …` match arm, a body
    /// read must not fall back to a default (`.unwrap_or*` / `.ok()`); use
    /// [`json_2xx`] / [`text_2xx`]. Scope: the match-arm shape, where 10 of
    /// PR1's 12 sites lived; the `if !status.is_success()` shape is held by
    /// its call sites' tests. `ALLOWED` is exact per file, so a fixed site
    /// must leave it.
    #[test]
    fn no_success_arm_reads_its_body_leniently() {
        const ALLOWED: &[(&str, usize, &str)] = &[
            (
                "routes/cluster.rs",
                1,
                "gpu_hold_op: its 2xx means the agent already held or released the GPU, so its \
                 state machine has its own PR (wt/b4-gpu-hold-body)",
            ),
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found: std::collections::BTreeMap<String, usize> = Default::default();
        let mut seen_arms = 0;
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                    continue;
                }
                let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
                let src = crate::test_src::own_code(&std::fs::read_to_string(&p).unwrap());
                let (arms, n) = lenient_success_arms(&src);
                seen_arms += arms;
                if n > 0 {
                    found.insert(rel, n);
                }
            }
        }
        assert!(seen_arms > 20, "the scan saw {seen_arms} success arms: the walk is broken, not the code");
        let allowed: std::collections::BTreeMap<String, usize> =
            ALLOWED.iter().map(|(f, n, _)| (f.to_string(), *n)).collect();
        assert_eq!(
            found, allowed,
            "a success arm reads its body with a default: a cut-off or non-JSON 2xx becomes an empty success. \
             Use crate::upstream_body::json_2xx / text_2xx (i460)"
        );
    }

    /// `(success arms, of which read a body leniently)` in `src`.
    fn lenient_success_arms(src: &str) -> (usize, usize) {
        let compact: String = src.chars().filter(|c| !c.is_whitespace()).collect();
        let (mut arms, mut n) = (0, 0);
        let mut from = 0;
        while let Some(i) = compact[from..].find("is_success()=>") {
            arms += 1;
            let start = from + i + "is_success()=>".len();
            let arm = arm_text(&compact[start..]);
            if is_lenient_read(arm) {
                n += 1;
            }
            from = start;
        }
        (arms, n)
    }

    /// The arm after `=>`: a `{…}` block, or an expression up to the first
    /// `,` at depth 0.
    fn arm_text(s: &str) -> &str {
        let b = s.as_bytes();
        let mut depth = 0i32;
        for (j, &c) in b.iter().enumerate() {
            match c {
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => {
                    depth -= 1;
                    if depth < 0 || (depth == 0 && b[0] == b'{') {
                        return &s[..=j];
                    }
                }
                b',' if depth == 0 => return &s[..j],
                _ => {}
            }
        }
        s
    }

    fn is_lenient_read(arm: &str) -> bool {
        let mut from = 0;
        while let Some(i) = arm[from..].find("().await.") {
            let at = from + i;
            let before = &arm[..at];
            let after = &arm[at + "().await.".len()..];
            let reads_body = before.ends_with(".text")
                || before.ends_with(".bytes")
                || before.ends_with(".json")
                || (before.ends_with('>') && before.contains(".json::<"));
            if reads_body && (after.starts_with("unwrap_or") || after.starts_with("ok()")) {
                return true;
            }
            from = at + 1;
        }
        false
    }

    #[test]
    fn the_guard_sees_each_lenient_shape_and_passes_the_fixed_ones() {
        let bad = [
            "Ok(r) if r.status().is_success() => { let v: Value = r.json().await.unwrap_or(json!({})); v }, Ok(r) => x,",
            "Ok(r) if r.status().is_success() => Ok(r.json::<Value>().await.unwrap_or(json!({}))), Ok(r) => x,",
            "Ok(r) if r.status().is_success() => { let t = r.text().await.unwrap_or_default(); t }",
            "Ok(r) if r.status().is_success() => r.json::<Value>().await.ok(),",
        ];
        for s in bad {
            assert_eq!(lenient_success_arms(s), (1, 1), "missed: {s}");
        }
        let good = [
            "Ok(r) if r.status().is_success() => json_2xx(r, \"n\").await, Ok(r) => { r.text().await.unwrap_or_default() }",
            "Ok(r) if r.status().is_success() => { let v = r.json::<Value>().await.map_err(|e| e.to_string())?; v }",
        ];
        for s in good {
            assert_eq!(lenient_success_arms(s), (1, 0), "false hit: {s}");
        }
    }
}
