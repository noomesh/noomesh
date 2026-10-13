// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo onboard --web` — the browser wizard, served from the binary itself
//! (no Python, no FastAPI). Mirrors `src/noomesh/onboard/web_wizard.py`:
//! same port (:7080), same 127.0.0.1-only bind, same routes, same SSE event
//! shapes — the frontend (`web_index.html`) is the Python wizard's inlined
//! page verbatim, so the browser-side contract is identical.
//!
//! Server: hand-rolled over `std::net::TcpListener` — deliberately NOT
//! axum/tokio (the crate is a blocking ureq/rustls stack) and not even
//! `tiny_http`: the route surface is 8 tiny routes, no request body is ever
//! parsed (answers arrive as a query param, exactly like the Python
//! frontend's `POST /answer?v=…`), and SSE is just a long-lived
//! `Connection: close` response written incrementally. Zero new deps.
//!
//! Concurrency model (mirrors the Python design 1:1):
//!   - the wizard steps run on the CALLING thread (borrowing `Globals`),
//!   - the accept loop + per-connection handlers run on plain threads
//!     holding `Arc<Bridge>` clones,
//!   - `Bridge` is the Rust `StepRunner`: steps emit events into a queue the
//!     SSE handler drains; prompts block on a Condvar until the browser
//!     POSTs `/answer` (Python blocks on `threading.Event` the same way),
//!   - `/abort` sets a flag and wakes every Condvar; the next emit/ask in
//!     the wizard unwinds via `panic_any(WizardAborted)` (Python raises
//!     `WizardAborted` from `emit()`), caught by `catch_unwind` in
//!     `run_web`.
//!
//! Routes (browser contract — see web_index.html):
//!   GET  /                 → the wizard page
//!   GET  /events           → SSE stream of {kind, text, data} events
//!   POST /answer?v=…       → unblock a pending prompt/confirm
//!   POST /abort            → abort the wizard
//!   POST /go-back /go-next → navigation (the Rust engine is linear: both
//!                            resume the pause; Back is never offered —
//!                            navigate events carry can_back:false)
//!   GET  /api/browse?path= → directory listing for the dir picker
//!   GET  /health           → {"running": bool}

use std::collections::VecDeque;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde_json::json;

const INDEX_HTML: &str = include_str!("web_index.html");

/// Grace period after the final DONE event before the server exits, so the
/// browser's EventSource receives it (Python sleeps 3s for the same reason).
const DONE_GRACE: Duration = Duration::from_secs(3);

/// Panic payload used to unwind the wizard on `/abort` — the Rust analogue
/// of Python's `WizardAborted` exception raised from `StepRunner.emit()`.
pub struct WizardAborted;

/// The web frontend's [`WizardUi`] implementation: a thin adapter from the
/// generic event/prompt seam onto the SSE [`Bridge`] (whose event shapes and
/// blocking semantics are the browser contract — unchanged from WP-W2; the
/// Bridge tests below remain the spec). Introduced when WP-W1 unified the
/// frontends under one trait: the console/TUI/web all drive the same steps.
pub(crate) struct WebUi(pub Arc<Bridge>);

impl super::event::WizardUi for WebUi {
    fn emit(&self, ev: super::event::UiEvent) {
        use super::event::UiEvent as E;
        match ev {
            E::StepStart { step, total, title } => {
                self.0.emit("step_start", &title, json!({"step": step, "total": total}))
            }
            E::StepDone { step, ok } => self.0.emit("step_done", "", json!({"step": step, "ok": ok})),
            E::Info(m) => self.0.emit("info", &m, json!({})),
            E::Success(m) => self.0.emit("success", &m, json!({})),
            E::Warning(m) => self.0.emit("warning", &m, json!({})),
            E::Error(m) => self.0.emit("error", &m, json!({})),
            E::Progress(m) => self.0.emit("progress", &m, json!({})),
            E::Dry(m) => self.0.emit("info", &format!("[dry-run] would: {m}"), json!({})),
            // Raw console lines and prompt-side hints are info/warning events
            // in the browser (same mapping the Sink enum used).
            E::Line(m) => self.0.emit("info", &m, json!({})),
            E::Note(m) => self.0.emit("warning", &m, json!({})),
        }
    }

    fn prompt(&self, req: &super::event::PromptRequest) -> String {
        use super::event::PromptKind as K;
        match &req.kind {
            // Bridge::ask owns the browser-side contract: hidden defaults
            // never ship to the DOM, required-with-no-default loops with a
            // "a value is required" warning, empty answer takes the default.
            K::Text { default, secret, required } => {
                self.0.ask(&req.label, default.as_deref().unwrap_or(""), *secret, *required)
            }
            K::Confirm { default } => {
                if self.0.confirm(&req.label, *default) { "y".into() } else { "n".into() }
            }
        }
    }

    /// The web wizard keeps WP-W2's behavior: the launching console still
    /// owns the terminal (streamed compose/pull output and any sudo prompt
    /// land there, next to the "Starting Noomesh setup wizard" banner).
    fn inherit_stdio(&self) -> bool {
        true
    }

    /// The browser can always re-present an invalid choice.
    fn can_reprompt(&self) -> bool {
        true
    }

    /// Per-step Next-button pause (the Bridge blocks until `/go-next`).
    fn wait_next(&self, step: u8, total: u8) {
        self.0.wait_next(step, total);
    }
}

#[derive(Default)]
struct AnswerSlot {
    value: Option<String>,
}

/// The Rust `StepRunner`: event queue out, blocking answers in.
pub struct Bridge {
    queue: Mutex<VecDeque<String>>,
    queue_cv: Condvar,
    answer: Mutex<AnswerSlot>,
    answer_cv: Condvar,
    nav: Mutex<bool>,
    nav_cv: Condvar,
    aborted: AtomicBool,
    done: AtomicBool,
}

impl Bridge {
    pub fn new() -> Self {
        Bridge {
            queue: Mutex::new(VecDeque::new()),
            queue_cv: Condvar::new(),
            answer: Mutex::new(AnswerSlot::default()),
            answer_cv: Condvar::new(),
            nav: Mutex::new(false),
            nav_cv: Condvar::new(),
            aborted: AtomicBool::new(false),
            done: AtomicBool::new(false),
        }
    }

    // ── wizard-side (may panic_any(WizardAborted) after /abort) ─────────

    fn check_aborted(&self) {
        if self.is_aborted() {
            std::panic::panic_any(WizardAborted);
        }
    }

    /// Queue an event for the SSE stream. Shape matches the Python wizard:
    /// `{"kind": …, "text": …, "data": {…}}`.
    pub fn emit(&self, kind: &str, text: &str, data: serde_json::Value) {
        self.check_aborted();
        let payload = json!({"kind": kind, "text": text, "data": data}).to_string();
        self.queue.lock().unwrap().push_back(payload);
        self.queue_cv.notify_all();
    }

    /// Emit a prompt event and block until the browser POSTs `/answer`.
    /// Empty answer → default; required with no default loops (parity with
    /// the console Asker's required-value loop).
    pub fn ask(&self, label: &str, default: &str, secret: bool, required: bool) -> String {
        loop {
            self.check_aborted();
            self.answer.lock().unwrap().value = None;
            // Never ship a hidden default into the DOM: for secret prompts
            // the browser sees no default, but an empty submit still takes
            // the stored default server-side.
            let shown_default = if secret { "" } else { default };
            self.emit("prompt", label, json!({"default": shown_default, "secret": secret}));
            let v = self.wait_answer();
            if !v.is_empty() {
                return v;
            }
            if !default.is_empty() || !required {
                return default.to_string();
            }
            self.emit("warning", "a value is required", json!({}));
        }
    }

    /// Emit a confirm event and block for a y/n answer (empty → default).
    pub fn confirm(&self, label: &str, default: bool) -> bool {
        self.check_aborted();
        self.answer.lock().unwrap().value = None;
        self.emit("confirm", label, json!({"default": default}));
        let v = self.wait_answer();
        if v.is_empty() {
            return default;
        }
        matches!(v.to_ascii_lowercase().as_str(), "y" | "yes" | "true" | "1")
    }

    fn wait_answer(&self) -> String {
        let mut slot = self.answer.lock().unwrap();
        loop {
            if self.is_aborted() {
                drop(slot);
                std::panic::panic_any(WizardAborted);
            }
            if let Some(v) = slot.value.take() {
                return v;
            }
            let (s, _) = self.answer_cv.wait_timeout(slot, Duration::from_millis(200)).unwrap();
            slot = s;
        }
    }

    /// Emit a navigate event (Next button; Back is never offered — the Rust
    /// engine is linear) and block until the browser clicks through.
    pub fn wait_next(&self, step: u8, total: u8) {
        self.check_aborted();
        *self.nav.lock().unwrap() = false;
        self.emit("navigate", "", json!({"step": step, "total": total, "can_back": false}));
        let mut clicked = self.nav.lock().unwrap();
        loop {
            if self.is_aborted() {
                drop(clicked);
                std::panic::panic_any(WizardAborted);
            }
            if *clicked {
                return;
            }
            let (c, _) = self.nav_cv.wait_timeout(clicked, Duration::from_millis(200)).unwrap();
            clicked = c;
        }
    }

    // ── server-side ──────────────────────────────────────────────────────

    /// Pop the next queued event, waiting up to `timeout`.
    fn pop_event(&self, timeout: Duration) -> Option<String> {
        let mut q = self.queue.lock().unwrap();
        if let Some(ev) = q.pop_front() {
            return Some(ev);
        }
        let (mut q, _) = self.queue_cv.wait_timeout(q, timeout).unwrap();
        q.pop_front()
    }

    /// Browser POSTed `/answer?v=…`.
    pub fn answer(&self, value: &str) {
        self.answer.lock().unwrap().value = Some(value.to_string());
        self.answer_cv.notify_all();
    }

    /// Browser POSTed `/go-next` or `/go-back` (both resume — linear engine).
    pub fn navigate(&self) {
        *self.nav.lock().unwrap() = true;
        self.nav_cv.notify_all();
    }

    /// Browser POSTed `/abort` — wake everything; the wizard unwinds on its
    /// next emit/ask.
    pub fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
        self.answer_cv.notify_all();
        self.nav_cv.notify_all();
        self.queue_cv.notify_all();
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }

    fn set_done(&self) {
        self.done.store(true, Ordering::SeqCst);
        self.queue_cv.notify_all();
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }
}

// ── HTTP server ──────────────────────────────────────────────────────────

pub struct Server {
    pub port: u16,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Bind 127.0.0.1:`port` (0 = ephemeral) and serve on a background thread.
/// Loopback-only on purpose: a setup wizard must not listen on the LAN
/// (Python binds host="127.0.0.1" identically).
pub fn start_server(bridge: Arc<Bridge>, port: u16) -> std::io::Result<Server> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    let handle = std::thread::spawn(move || loop {
        if sd.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let b = bridge.clone();
                let sd2 = sd.clone();
                std::thread::spawn(move || {
                    let _ = handle_conn(stream, &b, &sd2);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    });
    Ok(Server { port, shutdown, handle: Some(handle) })
}

fn handle_conn(mut stream: TcpStream, bridge: &Bridge, shutdown: &AtomicBool) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    // Read the two headers that decide whether this request is ours; no
    // route parses a body (answers travel as query params, matching the
    // frontend's `fetch('/answer?v=…', {method:'POST'})`).
    let mut host = String::new();
    let mut origin: Option<String> = None;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "host" => host = v.trim().to_string(),
                "origin" => origin = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    let port = stream.local_addr()?.port();
    if let Some(why) = refuse(&method, &host, origin.as_deref(), port) {
        return respond(&mut stream, 403, "text/plain", why.as_bytes());
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target.as_str(), ""),
    };

    match (method.as_str(), path) {
        ("GET", "/") => respond(&mut stream, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        ("GET", "/events") => stream_events(&mut stream, bridge, shutdown),
        ("POST", "/answer") => {
            bridge.answer(&query_param(query, "v").unwrap_or_default());
            respond_json(&mut stream, &json!({"ok": true}))
        }
        ("POST", "/abort") => {
            bridge.abort();
            respond_json(&mut stream, &json!({"ok": true}))
        }
        ("POST", "/go-back") | ("POST", "/go-next") => {
            bridge.navigate();
            respond_json(&mut stream, &json!({"ok": true}))
        }
        ("GET", "/api/browse") => {
            let path = query_param(query, "path").unwrap_or_else(|| "/".to_string());
            respond_json(&mut stream, &browse_dirs(&path))
        }
        ("GET", "/health") => respond_json(&mut stream, &json!({"running": !bridge.is_done()})),
        _ => respond(&mut stream, 404, "text/plain", b"not found"),
    }
}

fn stream_events(stream: &mut TcpStream, bridge: &Bridge, shutdown: &AtomicBool) -> std::io::Result<()> {
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
    )?;
    stream.flush()?;
    loop {
        // Drain-before-exit: the final DONE event is queued before the done
        // flag flips, so it always reaches the browser first.
        if let Some(ev) = bridge.pop_event(Duration::from_millis(250)) {
            stream.write_all(format!("data: {ev}\n\n").as_bytes())?;
            stream.flush()?;
        } else if bridge.is_done() || shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
    }
}

/// Why a request is not this wizard's own browser tab, or None.
///
/// The listener is loopback-only, which stops the network but not the
/// browser: while the wizard runs, any page the operator has open can POST
/// `/answer?v=…` blind (a form POST needs no preflight), and a DNS-rebinding
/// page can read `/events` and `/api/browse`.
/// Two checks close both: the Host must be this listener (rebinding changes
/// it), and a POST carrying a foreign Origin is refused — browsers attach
/// Origin to every cross-site POST, so one that lacks it is a local tool.
pub(crate) fn refuse(method: &str, host: &str, origin: Option<&str>, port: u16) -> Option<String> {
    let ours = |h: &str| {
        let h = h.trim().trim_start_matches("http://");
        h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}")
            || (port == 80 && (h == "127.0.0.1" || h == "localhost"))
    };
    if !ours(host) {
        return Some(format!("this wizard answers only 127.0.0.1:{port}, not {host}"));
    }
    if method == "POST" {
        if let Some(o) = origin {
            if !ours(o) {
                return Some(format!("a POST from {o} is not this wizard's page"));
            }
        }
    }
    None
}

fn respond(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn respond_json(stream: &mut TcpStream, v: &serde_json::Value) -> std::io::Result<()> {
    respond(stream, 200, "application/json", v.to_string().as_bytes())
}

/// Directory listing for the browser's dir picker (parity with the Python
/// `/api/browse`): non-hidden directories only, name-sorted case-insensitively,
/// errors reported in-band as `{"entries": [], "error": …}`.
fn browse_dirs(path: &str) -> serde_json::Value {
    let rd = match std::fs::read_dir(path) {
        Ok(rd) => rd,
        Err(e) => return json!({"entries": [], "error": e.to_string()}),
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    let entries: Vec<serde_json::Value> =
        names.into_iter().map(|n| json!({"name": n, "type": "dir"})).collect();
    json!({"entries": entries})
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Decode %XX escapes and `+` (the frontend uses encodeURIComponent, which
/// produces %20 for spaces — `+` handled anyway for robustness).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── entry point ──────────────────────────────────────────────────────────

/// WSL2-aware browser open (parity with Python's `_open_browser`).
fn open_browser(url: &str) {
    let is_wsl2 = std::fs::read_to_string("/proc/version")
        .map(|v| v.to_lowercase().contains("microsoft"))
        .unwrap_or(false);
    let attempt = if is_wsl2 {
        std::process::Command::new("cmd.exe")
            .args(["/c", "start", url])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
    } else {
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
    };
    let _ = attempt; // best-effort — the printed URL is the fallback
}

/// Drive the full onboard flow behind the embedded web server. Blocks until
/// the wizard completes or the browser aborts; returns the exit code.
pub fn run_web(
    g: &crate::Globals,
    port: u16,
    non_interactive: bool,
    dry_run: bool,
    reconfigure: bool,
    skip: super::Skip,
    grace: Duration,
) -> i32 {
    let bridge = Arc::new(Bridge::new());
    let server = match start_server(bridge.clone(), port) {
        Ok(s) => s,
        Err(e) => {
            crate::ui::failed(&format!("could not bind web wizard to 127.0.0.1:{port}: {e}"), None);
            return 1;
        }
    };
    serve_wizard(g, bridge, server, non_interactive, dry_run, reconfigure, skip, grace)
}

/// Everything `run_web` does once the listener is bound. Split out so a test
/// can bind port 0 itself, read the OS-assigned port off `Server`, and hand
/// the live listener over — no pick-then-release window for a parallel test
/// to steal the port in.
#[allow(clippy::too_many_arguments)]
fn serve_wizard(
    g: &crate::Globals,
    bridge: Arc<Bridge>,
    server: Server,
    non_interactive: bool,
    dry_run: bool,
    reconfigure: bool,
    skip: super::Skip,
    grace: Duration,
) -> i32 {
    let url = format!("http://127.0.0.1:{}", server.port);
    println!("Starting Noomesh setup wizard at {url}");
    println!("Open this URL in your browser. Press Ctrl+C to stop.\n");
    if !non_interactive {
        open_browser(&url);
    }

    // Silence the WizardAborted unwind (it's control flow, not a crash);
    // every other panic still reports through the previous hook.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload().downcast_ref::<WizardAborted>().is_none() {
            prev_hook(info);
        }
    }));

    let web_ui = WebUi(bridge.clone());
    let mut ctx = super::build_ctx(g, &web_ui, non_interactive, dry_run, skip);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::drive(&mut ctx, reconfigure)
    }));

    let aborted = bridge.is_aborted() || result.is_err();
    let interrupted = aborted || ctx.state.interrupted;
    // Final DONE event — same shape as Python's steps_core (gateway_url is
    // used by the frontend for the dashboard redirect).
    if !bridge.is_aborted() {
        // https always: the gateway serves no plaintext listener, so the
        // dashboard redirect has exactly one scheme it could be right with.
        let proto = "https";
        bridge.emit(
            "done",
            if interrupted { "Setup interrupted." } else { "Setup complete." },
            json!({"gateway_url": format!("{proto}://localhost:8080")}),
        );
    }
    bridge.set_done();
    // Let the browser's EventSource drain the final event before we exit.
    std::thread::sleep(grace);
    server.stop();

    if aborted {
        println!("\nSetup aborted from the browser. Run 'noo onboard' to try again.");
    }
    // An explicit browser abort is a clean user choice (exit 0, same as the
    // Python wizard). A wizard that RAN and failed carries `drive`'s verdict
    // (the same `Outcome` the console frontend exits on); one that panicked
    // is a failure.
    match result {
        Ok(code) if !bridge.is_aborted() => code,
        Err(_) if !bridge.is_aborted() => 1,
        _ => 0,
    }
}

/// Production grace period (exposed for `mod.rs`; tests pass a short one).
pub const GRACE: Duration = DONE_GRACE;

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    /// One-shot HTTP request; returns the full raw response (headers + body).
    /// Works because every non-SSE route replies `Connection: close`.
    fn http(port: u16, method: &str, target: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).unwrap();
        let mut buf = String::new();
        let _ = s.read_to_string(&mut buf);
        buf
    }

    /// Upper bound on waiting for an SSE event. A bound on the whole wait,
    /// never on the gap between two events: the e2e wizard shells out to
    /// real host probes (`docker info` alone takes ~3.5s on an idle box),
    /// and under a parallel build that gap passed the old 10s per-read
    /// timeout, so the reader gave up mid-wizard ("no done event"). A
    /// loaded run measured ~30s end to end; this is 3x that, and a real
    /// hang still fails instead of blocking forever.
    const SSE_WAIT: Duration = Duration::from_secs(90);

    /// Open the SSE stream and read `data:` lines until `pred` matches one
    /// (returning all seen so far), the stream ends, or `SSE_WAIT` passes.
    fn read_sse_until(port: u16, pred: impl Fn(&str) -> bool) -> Vec<String> {
        let deadline = std::time::Instant::now() + SSE_WAIT;
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(format!("GET /events HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).unwrap();
        let mut reader = BufReader::new(s);
        let mut seen = Vec::new();
        loop {
            // Each read may block only for what is left of the one deadline.
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return seen;
            }
            reader.get_ref().set_read_timeout(Some(left)).unwrap();
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return seen,
                Ok(_) => {
                    if let Some(payload) = line.trim_end().strip_prefix("data: ") {
                        let done = pred(payload);
                        seen.push(payload.to_string());
                        if done {
                            return seen;
                        }
                    }
                }
            }
        }
    }

    /// Install the WizardAborted-silencing hook (idempotent enough for tests;
    /// chains to the previous hook for real panics).
    fn silence_aborts() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<WizardAborted>().is_none() {
                prev(info);
            }
        }));
    }

    #[test]
    fn a_foreign_host_is_refused_and_a_foreign_origin_cannot_answer() {
        let r = super::refuse("GET", "evil.example:7080", None, 7080);
        assert!(r.is_some(), "DNS rebinding changes the Host; that is the tell");
        assert_eq!(super::refuse("GET", "127.0.0.1:7080", None, 7080), None);
        assert_eq!(super::refuse("GET", "localhost:7080", None, 7080), None);
        // a cross-site POST always carries the attacker's Origin
        assert!(super::refuse("POST", "127.0.0.1:7080", Some("http://evil.example"), 7080).is_some());
        // the wizard's own tab, and a local tool with no Origin at all
        assert_eq!(super::refuse("POST", "127.0.0.1:7080", Some("http://127.0.0.1:7080"), 7080), None);
        assert_eq!(super::refuse("POST", "localhost:7080", None, 7080), None);
    }

    #[test]
    fn a_blind_cross_site_post_does_not_reach_the_wizard() {
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge.clone(), 0).unwrap();
        let port = server.port;
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(format!("POST /answer?v=pwned HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example\r\n\r\n").as_bytes()).unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    }

    #[test]
    fn index_served_and_unknown_route_404s() {
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge, 0).unwrap();
        let port = server.port;

        let resp = http(port, "GET", "/");
        assert!(resp.starts_with("HTTP/1.1 200"), "got: {}", &resp[..resp.len().min(80)]);
        assert!(resp.contains("Noomesh Setup Wizard"));
        // The frontend contract this port relies on must be present verbatim.
        assert!(resp.contains("new EventSource('/events')"));
        assert!(resp.contains("/answer?v="));

        let resp = http(port, "GET", "/nope");
        assert!(resp.starts_with("HTTP/1.1 404"));
        server.stop();
    }

    #[test]
    fn sse_prompt_roundtrip_unblocks_ask() {
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge.clone(), 0).unwrap();
        let port = server.port;

        let b = bridge.clone();
        let wizard = std::thread::spawn(move || {
            b.emit("step_start", "Environment", json!({"step": 2, "total": 8}));
            let v = b.ask("Node ID", "fallback", false, false);
            b.set_done();
            v
        });

        // The browser sees step_start then the prompt (with its default).
        let seen = read_sse_until(port, |p| p.contains("\"kind\":\"prompt\""));
        assert!(seen.iter().any(|p| p.contains("\"kind\":\"step_start\"") && p.contains("Environment")));
        let prompt = seen.last().unwrap();
        assert!(prompt.contains("Node ID") && prompt.contains("\"default\":\"fallback\""));

        // Browser POSTs the answer (percent-encoded, like encodeURIComponent).
        let resp = http(port, "POST", "/answer?v=my%20node");
        assert!(resp.contains("{\"ok\":true}"));
        assert_eq!(wizard.join().unwrap(), "my node");
        server.stop();
    }

    #[test]
    fn confirm_roundtrip_and_empty_answer_takes_default() {
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge.clone(), 0).unwrap();
        let port = server.port;

        let b = bridge.clone();
        let wizard = std::thread::spawn(move || {
            let yes = b.confirm("Proceed?", false);
            let dflt = b.confirm("Again?", true);
            b.set_done();
            (yes, dflt)
        });

        read_sse_until(port, |p| p.contains("\"kind\":\"confirm\""));
        http(port, "POST", "/answer?v=y");
        // Second confirm: empty answer → default (true).
        std::thread::sleep(Duration::from_millis(100));
        http(port, "POST", "/answer?v=");
        assert_eq!(wizard.join().unwrap(), (true, true));
        server.stop();
    }

    #[test]
    fn secret_prompt_never_ships_default_to_browser() {
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge.clone(), 0).unwrap();
        let port = server.port;

        let b = bridge.clone();
        let wizard = std::thread::spawn(move || {
            let v = b.ask("API key", "sk-STORED-SECRET", true, false);
            b.set_done();
            v
        });

        let seen = read_sse_until(port, |p| p.contains("\"kind\":\"prompt\""));
        let prompt = seen.last().unwrap();
        assert!(prompt.contains("\"secret\":true"));
        assert!(!prompt.contains("STORED-SECRET"), "hidden default leaked into SSE: {prompt}");
        // Empty submit still takes the stored default server-side.
        http(port, "POST", "/answer?v=");
        assert_eq!(wizard.join().unwrap(), "sk-STORED-SECRET");
        server.stop();
    }

    #[test]
    fn abort_unblocks_pending_prompt_and_unwinds() {
        silence_aborts();
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge.clone(), 0).unwrap();
        let port = server.port;

        let b = bridge.clone();
        let wizard = std::thread::spawn(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                b.ask("Blocked forever?", "", false, true)
            }))
        });

        read_sse_until(port, |p| p.contains("\"kind\":\"prompt\""));
        let resp = http(port, "POST", "/abort");
        assert!(resp.contains("{\"ok\":true}"));

        let result = wizard.join().unwrap();
        let payload = result.expect_err("abort must unwind the pending ask");
        assert!(payload.downcast_ref::<WizardAborted>().is_some());
        assert!(bridge.is_aborted());
        // Post-abort, any further emit also unwinds (Python: emit raises).
        let b = bridge.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            b.emit("info", "after abort", json!({}));
        }));
        assert!(r.is_err());
        server.stop();
    }

    #[test]
    fn navigate_unblocks_step_pause() {
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge.clone(), 0).unwrap();
        let port = server.port;

        let b = bridge.clone();
        let wizard = std::thread::spawn(move || {
            b.wait_next(3, 8);
            b.set_done();
        });

        let seen = read_sse_until(port, |p| p.contains("\"kind\":\"navigate\""));
        assert!(seen.last().unwrap().contains("\"can_back\":false"));
        http(port, "POST", "/go-next");
        wizard.join().unwrap();
        server.stop();
    }

    #[test]
    fn browse_lists_only_visible_dirs() {
        let tmp = std::env::temp_dir().join(format!("noo-web-browse-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("Beta")).unwrap();
        std::fs::create_dir_all(tmp.join("alpha")).unwrap();
        std::fs::create_dir_all(tmp.join(".hidden")).unwrap();
        std::fs::write(tmp.join("file.txt"), "x").unwrap();

        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge, 0).unwrap();
        let resp = http(
            server.port,
            "GET",
            &format!("/api/browse?path={}", tmp.display().to_string().replace('/', "%2F")),
        );
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        let names: Vec<&str> =
            v["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["alpha", "Beta"]); // case-insensitive sort, no hidden, no files

        // Error path stays in-band (Python parity), not an HTTP error.
        let resp = http(server.port, "GET", "/api/browse?path=%2Fdoes%2Fnot%2Fexist");
        assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("\"error\""));
        server.stop();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn percent_decode_cases() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%2Fetc%2Fssl"), "/etc/ssl");
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
        assert_eq!(percent_decode("trail%2"), "trail%2");
    }

    #[test]
    fn query_param_extracts_value() {
        assert_eq!(query_param("v=hello&x=1", "v").as_deref(), Some("hello"));
        assert_eq!(query_param("x=1", "v"), None);
        assert_eq!(query_param("v=", "v").as_deref(), Some(""));
    }

    /// End-to-end, headless (no TTY needed — web mode is meant to run
    /// detached from a terminal): the real onboard flow behind the real
    /// server, in --dry-run + --non-interactive so nothing on the host is
    /// touched and no browser interaction is required. Asserts the wizard
    /// runs to a final DONE event carrying the dashboard gateway_url and
    /// that run_web exits 0.
    #[test]
    fn e2e_dry_run_headless_reaches_done() {
        silence_aborts();
        // Hermetic repo root: an empty dir is never "already onboarded", so
        // the guard can't short-circuit the run on a configured dev host.
        // (No other unit test reads NOO_REPO_ROOT — checked before adding.)
        let root = std::env::temp_dir().join(format!("noo-web-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::env::set_var("NOO_REPO_ROOT", &root);
        let g = crate::Globals { json: false, verbose: false, gateway_override: None, timeout_secs: None, token: None, quiet: false };
        // Bind :0 and keep the listener: the OS-assigned port is read off
        // the live `Server` and the server is handed to the wizard as-is.
        // (Picking a port, releasing it, then letting run_web re-bind it left
        // a window for a parallel test's :0 bind to take it — "Address
        // already in use" under --test-threads.)
        let bridge = Arc::new(Bridge::new());
        let server = start_server(bridge.clone(), 0).unwrap();
        let port = server.port;
        let skip =
            super::super::Skip {
                tailscale: true,
                security: true,
                storage: true,
                services: true,
                model: true,
                channels: true,
                // Prerequisites are probed against the HOST's docker/git, so a
                // wizard that includes them exits 1 on a box without docker
                // (correct: a missing prerequisite is a failure). This test is
                // about the event stream, so it walks one hermetic section.
                only: vec!["env".to_string()],
                ..Default::default()
            };

        std::thread::scope(|s| {
            let handle =
                s.spawn(|| serve_wizard(&g, bridge, server, true, true, false, skip, Duration::from_secs(2)));

            // The listener is already bound, so the first connect succeeds;
            // the wizard thread's progress is bounded by read_sse_until.
            let events = read_sse_until(port, |p| p.contains("\"kind\":\"done\""));
            let done = events.iter().find(|p| p.contains("\"kind\":\"done\"")).expect("no done event");
            assert!(done.contains("gateway_url"), "done event missing gateway_url: {done}");
            // Step events flowed over the same stream.
            assert!(events.iter().any(|p| p.contains("\"kind\":\"step_start\"")));
            assert_eq!(handle.join().unwrap(), 0);
        });
        let _ = std::fs::remove_dir_all(&root);
    }
}
