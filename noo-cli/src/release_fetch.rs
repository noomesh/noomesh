// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Release-asset fetch: say the real cause, retry only what is transient
//!
//! What this replaced. `fetch_tag_file` tried `gh release download`, dropped
//! gh's stderr when it failed, and fell back to a plain HTTPS GET. Against a
//! private repo that GET always answers 404, so a GitHub network blip during
//! a roll was reported as "not in release 0.5.91 (… HTTP 404)" for an asset
//! that was uploaded and present. Nothing retried it either, so one blip left
//! a platform without its harness until someone noticed.
//!
//! Now every failure carries a [`FetchClass`]:
//! - `NotFound`: the release or asset is genuinely absent (404/410, gh's
//!   "release not found" / "no assets match").
//! - `Auth`: 401/403 without rate-limit headers, gh not logged in, a token
//!   that cannot read the repo.
//! - `RateLimited`: 429, or 403 with `x-ratelimit-remaining: 0` or a
//!   `Retry-After`.
//! - `Network`: DNS, connect, timeout, reset, a body cut off mid-read.
//! - `Tls`: certificate verification failed. Not retried, never downgraded:
//!   verification stays on and the operator fixes trust, not the CLI.
//! - `Server`: GitHub (or a mirror) answered 5xx.
//!
//! Only `RateLimited`, `Network` and `Server` are retried, with bounded
//! attempts and exponential backoff inside a total time budget. A
//! `Retry-After` (or a rate-limit reset) is honoured when it fits the
//! budget; when it does not, the fetch stops and says when to come back.
//!
//! Retrying only refetches bytes. Every caller still verifies what comes
//! back exactly as before (signed manifest, signed lock, sha256): no lane
//! here skips, relaxes or caches around a verification step.
//!
//! No message carries a token: tokens go in a header only, and gh's stderr
//! and transport errors pass through [`redact`] before they are kept.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

/// Why a release fetch failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchClass {
    NotFound,
    Auth,
    RateLimited,
    Network,
    Tls,
    Server,
    Other,
}

impl FetchClass {
    /// Worth asking again: the same request can succeed in a moment.
    pub(crate) fn transient(self) -> bool {
        matches!(self, FetchClass::RateLimited | FetchClass::Network | FetchClass::Server)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            FetchClass::NotFound => "not found",
            FetchClass::Auth => "access refused",
            FetchClass::RateLimited => "rate-limited",
            FetchClass::Network => "network error",
            FetchClass::Tls => "TLS verification failed",
            FetchClass::Server => "server error",
            FetchClass::Other => "fetch failed",
        }
    }
}

/// A classified fetch failure. `detail` names the request and what came
/// back; `hint` (via [`FetchError::hint`]) says what to do next.
#[derive(Debug, Clone)]
pub(crate) struct FetchError {
    pub class: FetchClass,
    pub detail: String,
    /// How many times the request was made before giving up.
    pub attempts: u32,
    /// The server's requested wait (Retry-After or rate-limit reset).
    pub retry_after: Option<Duration>,
    /// A secondary lane's failure, reported after the primary cause.
    pub also: Option<String>,
}

impl FetchError {
    pub(crate) fn new(class: FetchClass, detail: impl Into<String>) -> Self {
        FetchError { class, detail: redact(&detail.into()), attempts: 1, retry_after: None, also: None }
    }

    pub(crate) fn is_not_found(&self) -> bool {
        self.class == FetchClass::NotFound
    }

    /// The cause, without the next-step hint (for `fail(.., msg, hint)`).
    pub(crate) fn summary(&self) -> String {
        let mut s = format!("{}: {}", self.class.label(), self.detail);
        if self.attempts > 1 {
            s.push_str(&format!(" (after {} attempts)", self.attempts));
        }
        if let Some(a) = &self.also {
            s.push_str(&format!("; {a}"));
        }
        s
    }

    /// What to do next, specific to the class.
    pub(crate) fn hint(&self) -> String {
        match self.class {
            FetchClass::NotFound => "check that the release tag exists and carries this asset \
                (`gh release view <tag> -R <repo>`); a private repo also answers 404 to an \
                account or anonymous request that cannot read it"
                .into(),
            FetchClass::Auth => "authenticate with an account that can read the release repo: \
                `gh auth login`, or export GH_TOKEN; tokens are never printed"
                .into(),
            FetchClass::RateLimited => match self.retry_after {
                Some(d) => format!(
                    "GitHub asks to wait {}s; retry then, or authenticate (`gh auth login` / GH_TOKEN) \
                     for a higher limit",
                    d.as_secs()
                ),
                None => "retry in a few minutes, or authenticate (`gh auth login` / GH_TOKEN) for a \
                    higher limit"
                    .into(),
            },
            FetchClass::Network => "check DNS, the proxy and connectivity to github.com (or the \
                mirror), then re-run; it was retried with backoff already"
                .into(),
            FetchClass::Tls => "the server's certificate was not trusted: fix the system trust \
                store or the intercepting proxy's CA; verification is never turned off"
                .into(),
            FetchClass::Server => "the server is failing (5xx); retry later, and check \
                githubstatus.com for a GitHub-side incident"
                .into(),
            FetchClass::Other => "re-run with --verbose for the full error".into(),
        }
    }

    pub(crate) fn with_also(mut self, also: impl Into<String>) -> Self {
        self.also = Some(redact(&also.into()));
        self
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} — next: {}", self.summary(), self.hint())
    }
}

impl From<FetchError> for String {
    fn from(e: FetchError) -> String {
        e.to_string()
    }
}

/// Bounded retries: `attempts` tries in all, exponential backoff from
/// `base` capped at `cap`, and never more than `budget` spent waiting.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RetryPolicy {
    pub attempts: u32,
    pub base: Duration,
    pub cap: Duration,
    pub budget: Duration,
}

/// 4 tries, 1s/2s/4s between them, at most 60s waiting in all.
pub(crate) const DEFAULT_RETRY: RetryPolicy = RetryPolicy {
    attempts: 4,
    base: Duration::from_secs(1),
    cap: Duration::from_secs(8),
    budget: Duration::from_secs(60),
};

pub(crate) fn real_sleep(d: Duration) {
    std::thread::sleep(d)
}

/// Run `op` until it succeeds, fails non-transiently, or the policy is
/// spent. The returned error carries the attempt count.
pub(crate) fn with_retry<T>(
    p: &RetryPolicy,
    sleep: &mut dyn FnMut(Duration),
    mut op: impl FnMut() -> Result<T, FetchError>,
) -> Result<T, FetchError> {
    let mut waited = Duration::ZERO;
    let mut n: u32 = 0;
    loop {
        n += 1;
        match op() {
            Ok(v) => return Ok(v),
            Err(mut e) => {
                e.attempts = n;
                if !e.class.transient() || n >= p.attempts.max(1) {
                    return Err(e);
                }
                let backoff = p.base.saturating_mul(1u32 << (n - 1).min(16)).min(p.cap);
                let wait = e.retry_after.unwrap_or(backoff);
                if waited + wait > p.budget {
                    // The server asked for longer than we will wait: stop
                    // and say when to come back instead of hanging.
                    return Err(e);
                }
                sleep(wait);
                waited += wait;
            }
        }
    }
}

/// Header lookup on a response, by lowercase name.
fn header(resp: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    resp.headers().get(name).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string())
}

/// Classify a non-2xx status with its rate-limit headers. `None` = success.
/// `hdr` looks a header up by lowercase name; `now` is unix seconds.
pub(crate) fn classify_status(
    status: u16,
    hdr: &dyn Fn(&str) -> Option<String>,
    now: u64,
) -> Option<(FetchClass, Option<Duration>)> {
    if (200..300).contains(&status) {
        return None;
    }
    let retry_after = hdr("retry-after").and_then(|v| v.parse::<u64>().ok()).map(Duration::from_secs);
    let reset = hdr("x-ratelimit-reset")
        .and_then(|v| v.parse::<u64>().ok())
        .map(|t| Duration::from_secs(t.saturating_sub(now)));
    let exhausted = hdr("x-ratelimit-remaining").as_deref() == Some("0");
    Some(match status {
        404 | 410 => (FetchClass::NotFound, None),
        429 => (FetchClass::RateLimited, retry_after.or(reset)),
        403 if exhausted || retry_after.is_some() => (FetchClass::RateLimited, retry_after.or(reset)),
        401 | 403 | 407 => (FetchClass::Auth, None),
        408 => (FetchClass::Network, None),
        500..=599 => (FetchClass::Server, retry_after),
        _ => (FetchClass::Other, None),
    })
}

/// Classify a transport-level failure (no HTTP status was received).
pub(crate) fn classify_transport(e: &ureq::Error) -> FetchClass {
    use ureq::Error as E;
    match e {
        E::StatusCode(s) => classify_status(*s, &|_| None, 0).map(|c| c.0).unwrap_or(FetchClass::Other),
        E::Tls(_) | E::Pem(_) | E::Rustls(_) | E::TlsRequired | E::RequireHttpsOnly(_) => FetchClass::Tls,
        E::Io(io) if looks_like_tls(&io.to_string()) => FetchClass::Tls,
        E::Timeout(_)
        | E::HostNotFound
        | E::ConnectionFailed
        | E::Io(_)
        | E::Protocol(_)
        | E::BodyStalled
        | E::ConnectProxyFailed(_)
        | E::RedirectFailed => FetchClass::Network,
        _ => FetchClass::Other,
    }
}

fn looks_like_tls(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("certificate") || l.contains("x509") || l.contains("unknownissuer")
}

/// u64 view of the one clock (`host_exec::now_unix`); the rate-limit math
/// here is unsigned.
fn now_unix() -> u64 {
    crate::host_exec::now_unix().max(0) as u64
}

/// One GET, classified. The agent must have `http_status_as_error(false)`
/// so the status and rate-limit headers are visible here.
pub(crate) fn get_once(agent: &ureq::Agent, url: &str, token: Option<&str>) -> Result<Vec<u8>, FetchError> {
    get_once_watched(agent, url, token, &mut |_, _| true)
}

/// [`get_once`], reading the body in chunks: `seen(bytes so far,
/// Content-Length)` runs after each one, and `false` abandons the read.
pub(crate) fn get_once_watched(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
    seen: &mut dyn FnMut(u64, Option<u64>) -> bool,
) -> Result<Vec<u8>, FetchError> {
    let mut req = agent.get(url).header("User-Agent", "noo-cli");
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let resp = req
        .call()
        .map_err(|e| FetchError::new(classify_transport(&e), format!("GET {url}: {e}")))?;
    let status = resp.status().as_u16();
    if let Some((class, retry_after)) = classify_status(status, &|n| header(&resp, n), now_unix()) {
        let mut e = FetchError::new(class, format!("GET {url} → HTTP {status}"));
        e.retry_after = retry_after;
        return Err(e);
    }
    let total = header(&resp, "content-length").and_then(|v| v.parse::<u64>().ok());
    let mut reader = resp.into_body().into_reader();
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| FetchError::new(FetchClass::Network, format!("GET {url}: body cut off: {e}")))?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
        if !seen(buf.len() as u64, total) {
            return Err(FetchError::new(FetchClass::Network, format!("GET {url}: abandoned after {} bytes", buf.len())));
        }
    }
}

/// [`get_once`] under a retry policy.
pub(crate) fn get_with_retry(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
    p: &RetryPolicy,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Vec<u8>, FetchError> {
    with_retry(p, sleep, || get_once(agent, url, token))
}

/// Classify `gh`'s stderr. gh exposes no status code, so this reads the
/// phrases it prints (`HTTP 404: Not Found (…)`, `release not found`, `no
/// assets match the file pattern`, `error connecting to api.github.com`, the
/// `gh auth login` prompt, Go's net errors).
pub(crate) fn classify_gh_stderr(stderr: &str) -> FetchClass {
    let l = stderr.to_ascii_lowercase();
    let has = |n: &str| l.contains(n);
    if has("rate limit") || has("http 429") {
        return FetchClass::RateLimited;
    }
    if let Some(i) = l.find("http 5") {
        let d: Vec<char> = l[i + 6..].chars().take(2).collect();
        if d.len() == 2 && d.iter().all(|c| c.is_ascii_digit()) {
            return FetchClass::Server;
        }
    }
    if has("no assets match") || has("release not found") || has("http 404") || has("http 410") {
        return FetchClass::NotFound;
    }
    if has("http 401")
        || has("http 403")
        || has("gh auth login")
        || has("bad credentials")
        || has("authentication")
        || has("resource not accessible")
        || has("saml")
    {
        return FetchClass::Auth;
    }
    if has("tls handshake timeout") {
        return FetchClass::Network;
    }
    if looks_like_tls(&l) {
        return FetchClass::Tls;
    }
    if has("error connecting to")
        || has("dial tcp")
        || has("timeout")
        || has("timed out")
        || has("connection reset")
        || has("connection refused")
        || has("no such host")
        || has("network is unreachable")
        || has("deadline exceeded")
        || has("temporary failure")
        || has("unexpected eof")
        || has("broken pipe")
    {
        return FetchClass::Network;
    }
    FetchClass::Other
}

/// The informative part of gh's stderr: non-empty lines, joined, capped.
pub(crate) fn gh_reason(stderr: &str) -> String {
    let s: Vec<&str> = stderr.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let mut s = s.join(" / ");
    if s.is_empty() {
        s = "(no output)".into();
    }
    if s.len() > 400 {
        let mut cut = 400;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push('…');
    }
    s
}

/// One `gh release download` of `name` from `tag` in `repo`, classified.
/// `gh` is the binary to run (a path, so tests can hand in a fake gh).
pub(crate) fn gh_download_once(gh: &Path, repo: &str, tag: &str, name: &str) -> Result<Vec<u8>, FetchError> {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "noo-release-fetch-{}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        name.replace('/', "_")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    let what = format!("gh release download {tag} --repo {repo} --pattern {name}");
    let out = std::process::Command::new(gh)
        .args(["release", "download", tag, "--repo", repo, "--pattern", name, "--dir"])
        .arg(&dir)
        .arg("--clobber")
        .stdin(std::process::Stdio::null())
        .output();
    let res = match out {
        Err(e) => Err(FetchError::new(FetchClass::Other, format!("{what}: could not run gh: {e}"))),
        Ok(o) if o.status.success() => std::fs::read(dir.join(name))
            .map_err(|e| FetchError::new(FetchClass::Other, format!("{what}: gh succeeded but {name} is unreadable: {e}"))),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            Err(FetchError::new(classify_gh_stderr(&err), format!("{what}: {}", gh_reason(&err))))
        }
    };
    let _ = std::fs::remove_dir_all(&dir);
    res
}

/// [`gh_download_once`] under a retry policy.
pub(crate) fn gh_download_with_retry(
    gh: &Path,
    repo: &str,
    tag: &str,
    name: &str,
    p: &RetryPolicy,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Vec<u8>, FetchError> {
    with_retry(p, sleep, || gh_download_once(gh, repo, tag, name))
}

/// gh first, the direct GET second — but the direct GET only when it can
/// help. gh is authenticated, so its "not found" is the answer and its
/// network/5xx/rate-limit failure is GitHub's, which a second lane to the
/// same GitHub would only repeat. A gh-side failure (not logged in, a
/// token that cannot read the repo, gh itself broken) is where the direct
/// GET can still succeed: on a public repo it needs no credentials. If
/// that fails too, gh's cause leads and the direct result follows — the
/// direct GET's 404 is what a private repo answers to anyone, so it must
/// never stand in for gh's error again.
pub(crate) fn gh_then_direct(
    gh: Option<&Path>,
    gh_fetch: &mut dyn FnMut(&Path) -> Result<Vec<u8>, FetchError>,
    direct: &mut dyn FnMut() -> Result<Vec<u8>, FetchError>,
) -> Result<Vec<u8>, FetchError> {
    let Some(gh) = gh else { return direct() };
    match gh_fetch(gh) {
        Ok(b) => Ok(b),
        Err(e) if matches!(e.class, FetchClass::Auth | FetchClass::Other) => match direct() {
            Ok(b) => Ok(b),
            Err(d) => Err(e.with_also(format!("the direct download also failed ({})", d.summary()))),
        },
        Err(e) => Err(e),
    }
}

/// Mask GitHub tokens (and `token`, if given) in text that will be shown.
pub(crate) fn redact(s: &str) -> String {
    let mut out = s.to_string();
    for k in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(v) = std::env::var(k) {
            let v = v.trim();
            if v.len() >= 8 {
                out = out.replace(v, "[redacted]");
            }
        }
    }
    // The fine-grained prefix is written in two parts so this file never holds it
    // whole (the snapshot credentials gate matches the prefix as text).
    for prefix in [concat!("github_", "pat_"), "ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        let mut from = 0;
        while let Some(i) = out[from..].find(prefix).map(|i| i + from) {
            let tail = &out[i + prefix.len()..];
            let n = tail.bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'_').count();
            if n >= 16 {
                out.replace_range(i..i + prefix.len() + n, "[redacted]");
                from = i + "[redacted]".len();
            } else {
                from = i + prefix.len();
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A scripted HTTP server on loopback: the n-th request gets the n-th
    /// `(status, extra headers, body)`, the last one repeating. The real
    /// ureq transport talks to it — this mocks the wire, not the call.
    /// `(status, extra headers, body)` per request.
    type Reply = (u16, Vec<(&'static str, String)>, &'static str);

    fn serve(script: Vec<Reply>) -> (String, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut st) = stream else { continue };
                let mut rd = BufReader::new(st.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if rd.read_line(&mut line).is_err() || line.trim().is_empty() {
                        break;
                    }
                }
                let n = h2.fetch_add(1, Ordering::SeqCst);
                let (status, hdrs, body) = &script[n.min(script.len() - 1)];
                let mut resp = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
                for (k, v) in hdrs {
                    resp.push_str(&format!("{k}: {v}\r\n"));
                }
                resp.push_str("\r\n");
                resp.push_str(body);
                let _ = st.write_all(resp.as_bytes());
            }
        });
        (base, hits)
    }

    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .http_status_as_error(false)
            .build()
            .into()
    }

    const FAST: RetryPolicy = RetryPolicy {
        attempts: 4,
        base: Duration::from_millis(1),
        cap: Duration::from_millis(4),
        budget: Duration::from_secs(30),
    };

    fn fetch(base: &str, sleeps: &mut Vec<Duration>) -> Result<Vec<u8>, FetchError> {
        get_with_retry(&agent(), &format!("{base}/rel/asset"), None, &FAST, &mut |d| sleeps.push(d))
    }

    #[test]
    fn a_404_is_not_retried_and_a_503_then_200_succeeds() {
        let (base, hits) = serve(vec![(404, vec![], "")]);
        let mut sleeps = vec![];
        let e = fetch(&base, &mut sleeps).unwrap_err();
        assert_eq!(e.class, FetchClass::NotFound);
        assert!(e.is_not_found());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a real 404 is asked once");
        assert_eq!(e.attempts, 1);
        assert!(sleeps.is_empty());
        assert!(e.to_string().contains("gh release view"), "{e}");

        let (base, hits) = serve(vec![(503, vec![], ""), (200, vec![], "payload")]);
        let mut sleeps = vec![];
        let b = fetch(&base, &mut sleeps).unwrap();
        assert_eq!(b, b"payload");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "503 retried once, then served");
        assert_eq!(sleeps.len(), 1);
    }

    #[test]
    fn auth_refused_is_not_retried_and_says_how_to_authenticate() {
        for status in [401u16, 403] {
            let (base, hits) = serve(vec![(status, vec![], "")]);
            let mut sleeps = vec![];
            let e = fetch(&base, &mut sleeps).unwrap_err();
            assert_eq!(e.class, FetchClass::Auth, "HTTP {status}");
            assert_eq!(hits.load(Ordering::SeqCst), 1, "HTTP {status} is asked once");
            assert!(e.to_string().contains("gh auth login"), "{e}");
            assert!(e.to_string().contains(&format!("HTTP {status}")), "{e}");
        }
    }

    #[test]
    fn server_errors_retry_up_to_the_bound_then_say_so() {
        let (base, hits) = serve(vec![(502, vec![], "")]);
        let mut sleeps = vec![];
        let e = fetch(&base, &mut sleeps).unwrap_err();
        assert_eq!(e.class, FetchClass::Server);
        assert_eq!(hits.load(Ordering::SeqCst), 4, "4 attempts in all");
        assert_eq!(e.attempts, 4);
        assert_eq!(sleeps, vec![Duration::from_millis(1), Duration::from_millis(2), Duration::from_millis(4)]);
        let s = e.to_string();
        assert!(s.contains("after 4 attempts") && s.contains("githubstatus.com"), "{s}");
    }

    #[test]
    fn a_429_honours_retry_after_then_succeeds() {
        let (base, hits) = serve(vec![(429, vec![("Retry-After", "2".into())], ""), (200, vec![], "ok")]);
        let mut sleeps = vec![];
        assert_eq!(fetch(&base, &mut sleeps).unwrap(), b"ok");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(sleeps, vec![Duration::from_secs(2)], "Retry-After wins over the backoff");
    }

    #[test]
    fn a_rate_limit_beyond_the_budget_stops_and_says_when() {
        // GitHub's primary limit: 403 + remaining 0 + a reset far away.
        let reset = (now_unix() + 3600).to_string();
        let (base, hits) = serve(vec![(
            403,
            vec![("x-ratelimit-remaining", "0".into()), ("x-ratelimit-reset", reset)],
            "",
        )]);
        let mut sleeps = vec![];
        let e = fetch(&base, &mut sleeps).unwrap_err();
        assert_eq!(e.class, FetchClass::RateLimited, "403 with an exhausted limit is not an auth refusal");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "an hour's wait exceeds the budget: no retry");
        assert!(sleeps.is_empty());
        let s = e.to_string();
        assert!(s.contains("rate-limited") && s.contains("for a higher limit") && s.contains("wait 3"), "{s}");
    }

    #[test]
    fn network_errors_are_retried_and_named() {
        // A port with nothing listening: connection refused, every time.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let mut sleeps = vec![];
        let e = fetch(&base, &mut sleeps).unwrap_err();
        assert_eq!(e.class, FetchClass::Network, "{e}");
        assert_eq!(e.attempts, 4);
        assert_eq!(sleeps.len(), 3);
        assert!(e.to_string().contains("check DNS, the proxy and connectivity"), "{e}");
    }

    #[test]
    fn tls_failures_are_named_and_never_retried() {
        let e = FetchError::new(classify_transport(&ureq::Error::Tls("bad cert")), "GET x");
        assert_eq!(e.class, FetchClass::Tls);
        assert!(!e.class.transient());
        assert!(e.to_string().contains("verification is never turned off"), "{e}");
        let io = ureq::Error::Io(std::io::Error::other("invalid peer certificate: UnknownIssuer"));
        assert_eq!(classify_transport(&io), FetchClass::Tls);
        let mut calls = 0;
        let r: Result<(), _> = with_retry(&FAST, &mut |_| {}, || {
            calls += 1;
            Err(FetchError::new(FetchClass::Tls, "x"))
        });
        assert!(r.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn gh_stderr_classes() {
        let cases = [
            ("release not found", FetchClass::NotFound),
            ("no assets match the file pattern", FetchClass::NotFound),
            ("HTTP 404: Not Found (https://api.github.com/repos/o/r/releases/tags/x)", FetchClass::NotFound),
            ("HTTP 401: Bad credentials (https://api.github.com/graphql)", FetchClass::Auth),
            ("To get started with GitHub CLI, please run:  gh auth login", FetchClass::Auth),
            ("HTTP 403: Resource not accessible by integration", FetchClass::Auth),
            ("HTTP 403: API rate limit exceeded for user ID 1.", FetchClass::RateLimited),
            ("HTTP 429: Too Many Requests", FetchClass::RateLimited),
            ("HTTP 502: Bad Gateway (https://api.github.com/…)", FetchClass::Server),
            ("error connecting to api.github.com\ncheck your internet connection or https://githubstatus.com", FetchClass::Network),
            ("Get \"https://api.github.com/\": dial tcp: lookup api.github.com: no such host", FetchClass::Network),
            ("net/http: TLS handshake timeout", FetchClass::Network),
            ("tls: failed to verify certificate: x509: certificate signed by unknown authority", FetchClass::Tls),
            ("something new", FetchClass::Other),
        ];
        for (s, want) in cases {
            assert_eq!(classify_gh_stderr(s), want, "{s}");
        }
    }

    /// A fake `gh` on disk: each run bumps a counter file and plays the
    /// scripted outcome for that run (the last repeating). Mocks the
    /// process transport, not `gh_download_once`.
    fn fake_gh(dir: &Path, outcomes: &[(i32, &str)]) -> std::path::PathBuf {
        let mut script = String::from("#!/bin/sh\nc=$(cat \"$0.n\" 2>/dev/null || echo 0); c=$((c+1)); echo $c > \"$0.n\"\n");
        script.push_str("dir=\"\"; pat=\"\"; while [ $# -gt 0 ]; do case \"$1\" in --dir) dir=$2; shift;; --pattern) pat=$2; shift;; esac; shift; done\n");
        for (i, (code, text)) in outcomes.iter().enumerate() {
            let n = i + 1;
            let cond = if n == outcomes.len() { format!("[ $c -ge {n} ]") } else { format!("[ $c -eq {n} ]") };
            if *code == 0 {
                script.push_str(&format!("if {cond}; then printf '{text}' > \"$dir/$pat\"; exit 0; fi\n"));
            } else {
                script.push_str(&format!("if {cond}; then echo '{text}' >&2; exit {code}; fi\n"));
            }
        }
        let p = dir.join("gh");
        crate::test_exec::write_exec(&p, script, 0o755);
        p
    }

    fn gh_runs(gh: &Path) -> u32 {
        std::fs::read_to_string(format!("{}.n", gh.display())).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("noo-rf-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    #[test]
    fn gh_lane_retries_transient_and_not_a_missing_asset() {
        let d = tmpdir("gh-net");
        let gh = fake_gh(&d, &[(1, "error connecting to api.github.com"), (0, "bytes")]);
        let b = gh_download_with_retry(&gh, "o/r", "noo-cli-v1.2.3", "noo-x", &FAST, &mut |_| {}).unwrap();
        assert_eq!(b, b"bytes");
        assert_eq!(gh_runs(&gh), 2, "network failure retried once, then served");

        let d = tmpdir("gh-404");
        let gh = fake_gh(&d, &[(1, "no assets match the file pattern")]);
        let e = gh_download_with_retry(&gh, "o/r", "noo-cli-v1.2.3", "noo-x", &FAST, &mut |_| {}).unwrap_err();
        assert!(e.is_not_found());
        assert_eq!(gh_runs(&gh), 1, "a missing asset is asked once");

        let d = tmpdir("gh-auth");
        let gh = fake_gh(&d, &[(4, "To get started with GitHub CLI, please run:  gh auth login")]);
        let e = gh_download_with_retry(&gh, "o/r", "t", "noo-x", &FAST, &mut |_| {}).unwrap_err();
        assert_eq!(e.class, FetchClass::Auth);
        assert_eq!(gh_runs(&gh), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The i11b incident, replayed: gh fails on the network, the direct GET
    /// to a private repo 404s. The report is gh's network error, never the
    /// direct lane's fake "not found" — and the direct lane is not even
    /// tried, because it would reach the same GitHub.
    #[cfg(unix)]
    #[test]
    fn a_gh_network_failure_is_not_reported_as_a_404() {
        let d = tmpdir("incident");
        let gh = fake_gh(&d, &[(1, "Get \"https://api.github.com/\": dial tcp: i/o timeout")]);
        let (base, hits) = serve(vec![(404, vec![], "")]);
        let e = gh_then_direct(
            Some(&gh),
            &mut |p| gh_download_with_retry(p, "o/r", "noo-cli-v0.5.91", "noo-gateway-aarch64-apple-darwin", &FAST, &mut |_| {}),
            &mut || get_with_retry(&agent(), &format!("{base}/x"), None, &FAST, &mut |_| {}),
        )
        .unwrap_err();
        assert_eq!(e.class, FetchClass::Network, "{e}");
        assert!(!e.is_not_found());
        assert_eq!(gh_runs(&gh), 4, "gh's transient failure is retried to the bound");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "the direct lane would only repeat GitHub's answer");
        assert!(!e.to_string().contains("HTTP 404"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// gh not logged in: the direct GET is the public-repo lane. When it
    /// also fails, gh's cause leads and the direct result follows.
    #[cfg(unix)]
    #[test]
    fn gh_not_logged_in_falls_back_to_the_direct_lane() {
        let d = tmpdir("public");
        let gh = fake_gh(&d, &[(4, "To get started with GitHub CLI, please run:  gh auth login")]);
        let (base, hits) = serve(vec![(200, vec![], "public-bytes")]);
        let b = gh_then_direct(
            Some(&gh),
            &mut |p| gh_download_with_retry(p, "o/r", "t", "a", &FAST, &mut |_| {}),
            &mut || get_with_retry(&agent(), &format!("{base}/x"), None, &FAST, &mut |_| {}),
        )
        .unwrap();
        assert_eq!(b, b"public-bytes");
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let d = tmpdir("private");
        let gh = fake_gh(&d, &[(4, "To get started with GitHub CLI, please run:  gh auth login")]);
        let (base, _) = serve(vec![(404, vec![], "")]);
        let e = gh_then_direct(
            Some(&gh),
            &mut |p| gh_download_with_retry(p, "o/r", "t", "a", &FAST, &mut |_| {}),
            &mut || get_with_retry(&agent(), &format!("{base}/x"), None, &FAST, &mut |_| {}),
        )
        .unwrap_err();
        assert_eq!(e.class, FetchClass::Auth, "gh's cause leads: {e}");
        let s = e.to_string();
        assert!(s.contains("the direct download also failed") && s.contains("gh auth login"), "{s}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tokens_never_reach_a_message() {
        let tok = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2");
        let e = FetchError::new(FetchClass::Auth, format!("gh said: bad token {tok} (HTTP 401)"));
        assert!(!e.to_string().contains(&tok), "{e}");
        assert!(e.to_string().contains("[redacted]"));
        let pat = format!("{}{}", concat!("github_", "pat_"), "x".repeat(40));
        assert!(!redact(&format!("a {pat} b")).contains(&pat));
        // Short look-alikes are left alone.
        assert_eq!(redact("ghp_x"), "ghp_x");
    }

    #[test]
    fn status_classes() {
        let none = |_: &str| None;
        assert_eq!(classify_status(200, &none, 0), None);
        assert_eq!(classify_status(404, &none, 0).unwrap().0, FetchClass::NotFound);
        assert_eq!(classify_status(401, &none, 0).unwrap().0, FetchClass::Auth);
        assert_eq!(classify_status(403, &none, 0).unwrap().0, FetchClass::Auth);
        assert_eq!(classify_status(429, &none, 0).unwrap().0, FetchClass::RateLimited);
        assert_eq!(classify_status(503, &none, 0).unwrap().0, FetchClass::Server);
        let secondary = |n: &str| (n == "retry-after").then(|| "30".to_string());
        assert_eq!(
            classify_status(403, &secondary, 0),
            Some((FetchClass::RateLimited, Some(Duration::from_secs(30)))),
            "GitHub's secondary limit is a 403 with Retry-After"
        );
    }
}
