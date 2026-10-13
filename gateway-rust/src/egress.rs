// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The channel egress boundary — the one place text is shaped before it
//! leaves the controller through a channel adapter (Google Chat, Telegram,
//! WhatsApp, and anything added later).
//!
//! A channel is OUTSIDE the trust boundary. A chat space has members the
//! operator did not vet one by one, a phone gets lost, a message is
//! forwarded, screenshotted, pasted into a support thread. The logs (Loki,
//! behind an Operator login) are where internals belong. So a channel never
//! carries internal hostnames or container names, internal addresses (the
//! tailnet 100.64.0.0/10 including the MagicDNS resolver 100.100.100.100,
//! the docker 172.16.0.0/12 bridge, loopback), `host:port` of stack
//! services, `*.ts.net` names, internal file paths, `NOO_*` setting names,
//! raw upstream error strings or JSON bodies, tokens, or stack traces.
//!
//! The trigger: an operator alert reached Google Chat as
//! "Backend vllm on host3 is advertised in the mesh but refuses connections
//! at its contract port ({"error":{"code":"backend_unreachable","message":
//! "dial tcp: lookup noo-vllm on 100.100.100.100:53: no such host",…}})" —
//! a container name, the MagicDNS resolver, a Go error and a JSON body in
//! one line, followed by a remediation for a different failure.
//!
//! Three tiers, one module:
//!
//! 1. **System-originated** ([`OperatorAlert`] → [`system`]): alerts and
//!    notices the platform sends on its own. Built STRUCTURED: a plain
//!    `summary` in the operator's own vocabulary (node names, backend kinds,
//!    task names, counts), one `investigate` command, and a `detail` that
//!    is LOGGED under the alert's reference id and never rendered. The
//!    summary is also run through [`scrub_system`], the aggressive
//!    scrubber, as defence in depth against a caller that interpolated
//!    something it should not have.
//! 2. **Error replies to a user's message** ([`error_reply`]): the channel
//!    gets one general sentence and a reference id; the raw error goes to
//!    the log with the same id.
//! 3. **Everything else, including assistant-authored replies**
//!    ([`outbound`]): the model's answers are the product and are not
//!    rewritten, but tool output can carry internals into an answer. Every
//!    adapter transport runs its text through [`scrub_internals`], which
//!    masks ONLY the internal shapes above (each becomes `[internal]`) and
//!    leaves ordinary text — a user's own 192.168.x LAN, a public URL, a
//!    time of day — untouched. This is the FLOOR: tiers 1 and 2 pass
//!    through it too, on their way out.
//!
//! `tests/test_channel_egress_guard.py` holds the wiring: every adapter
//! transport calls [`outbound`] before it posts, no other file builds a
//! channel API URL, the alert funnel only hands [`ChannelText`] to the
//! wire, and no Python code reaches an adapter API except through the
//! gateway's `/api/channels/send` (which lands on the same transports).

use regex::{Captures, Regex};
use std::sync::LazyLock;

/// The token every masked span becomes. Neutral on purpose: it says
/// "something was here" without hinting at what.
pub const MASK: &str = "[internal]";

/// Text that has been through the egress boundary. The field is private:
/// the only way to get one is [`system`], [`error_reply_text`] or
/// [`outbound`], so a function that takes `&ChannelText` cannot be handed a
/// raw string by mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelText(String);

impl ChannelText {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ChannelText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A fresh reference id: short enough to read aloud, unique enough to grep
/// (`noo logs search ref-3f9c2b1e0a`). Logged on the same line as the
/// detail it stands for.
pub fn new_ref() -> String {
    let u = uuid::Uuid::new_v4().simple().to_string();
    format!("ref-{}", &u[..10])
}

// ── Tier 1: system-originated ───────────────────────────────────────────

/// A system-originated message, as structured data.
///
/// What may reach a channel, and was decided on purpose: node names
/// (`host3`), backend kinds (`vllm`), task names, service names the
/// operator types in `noo` commands, counts, durations, and `noo` commands
/// themselves. These are the operator's own vocabulary — they are what
/// `noo cluster status` prints and what the operator named. What may not:
/// everything in the module docs. `detail` is where the rest goes.
#[derive(Debug, Clone, Default)]
pub struct OperatorAlert {
    /// Stable dotted event name (`autonomy.backend_unreachable`).
    pub kind: String,
    /// Cooldown scope (`host3:vllm`, a task id, `cluster`).
    pub target: String,
    /// One line of what happened, in plain words. Rendered.
    pub summary: String,
    /// The raw evidence — upstream error, body, addresses. LOGGED under
    /// the reference id, never rendered for a channel.
    pub detail: String,
    /// The one command that starts the investigation. Rendered. When
    /// `None`, the rendering points at the log line instead.
    pub investigate: Option<String>,
    /// A CONDITION rather than an event: it holds until something fixes it
    /// and is re-evaluated every tick. Persisting alerts are sent once at
    /// onset, reminded on a stretching schedule, and closed by a "recovered"
    /// message (see `operator_alert`); the caller's cooldown is ignored.
    pub persisting: bool,
}

impl OperatorAlert {
    pub fn new(kind: &str, target: &str, summary: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            target: target.to_string(),
            summary: summary.into(),
            ..Default::default()
        }
    }
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
    /// Mark this alert as a persisting condition (see [`OperatorAlert::persisting`]).
    pub fn persisting(mut self) -> Self {
        self.persisting = true;
        self
    }
    pub fn investigate(mut self, cmd: impl Into<String>) -> Self {
        self.investigate = Some(cmd.into());
        self
    }
}

/// Render a system message for a channel. The ONLY way an operator alert
/// becomes channel text.
///
/// Shape: the (scrubbed) summary, then the one command, then the reference
/// id the log line carries:
///
/// ```text
/// 🔌 Backend `vllm` on `host3` is advertised but the node agent cannot resolve its address.
/// Next: `noo cluster verify host3`
/// Ref: ref-3f9c2b1e0a (detail in the gateway log: `noo logs search ref-3f9c2b1e0a`)
/// ```
pub fn system(alert: &OperatorAlert, reference: &str) -> ChannelText {
    ChannelText(scrub_internals(&system_item(alert, reference, None)))
}

/// A human duration for "it lasted ...": `45s`, `12m`, `2h 5m`, `1d 3h`.
pub fn human_duration(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {}h", s / 86_400, (s % 86_400) / 3600)
    }
}

/// One alert's lines: the scrubbed summary, the one command, the reference.
/// The ONE renderer behind a single alert, a grouped alert and a recovered
/// message, so what is allowed to leave is decided in this function and
/// nowhere else. `detail` is never read. `recovered_after` (seconds) marks
/// a "this is fine now" message and states how long the condition lasted.
fn system_item(alert: &OperatorAlert, reference: &str, recovered_after: Option<i64>) -> String {
    let mut out = scrub_system(alert.summary.trim());
    if let Some(secs) = recovered_after {
        out.push_str(&format!(" It lasted {}.", human_duration(secs)));
    }
    if let Some(cmd) = alert.investigate.as_deref().filter(|c| !c.trim().is_empty()) {
        out.push_str("\nNext: `");
        out.push_str(cmd.trim());
        out.push('`');
    }
    out.push_str(&format!(
        "\nRef: {reference} (detail in the gateway log: `noo logs search {reference}`)"
    ));
    out
}

/// One alert, or a recovery, as channel text. `recovered_after` as in
/// [`system_item`]; the summary of a recovery says what is fine again.
pub fn system_recovered(alert: &OperatorAlert, reference: &str, lasted_secs: i64) -> ChannelText {
    ChannelText(scrub_internals(&system_item(alert, reference, Some(lasted_secs))))
}

/// Alerts raised in the same evaluation pass, as ONE message with one entry
/// each (summary, Next, Ref). Same renderer as [`system`], so grouping adds
/// no new way for detail to leave. A single entry renders exactly as
/// [`system`] / [`system_recovered`] would.
pub fn system_group(items: &[(&OperatorAlert, &str, Option<i64>)]) -> ChannelText {
    if let [(alert, reference, recovered)] = items {
        return ChannelText(scrub_internals(&system_item(alert, reference, *recovered)));
    }
    let mut out = format!("{} operator alerts:", items.len());
    for (i, (alert, reference, recovered)) in items.iter().enumerate() {
        out.push_str(&format!("\n\n{}. {}", i + 1, system_item(alert, reference, *recovered)));
    }
    ChannelText(scrub_internals(&out))
}

/// Render a system action's report for a channel.
///
/// `cluster_health`, `security_audit` and `channel_keepalive` are written
/// by the platform, not by a model, so their channel text is tier 1 like an
/// alert's summary: the general lines (counts, node and channel names) go
/// through [`scrub_system`], and when the report has evidence — a probe's
/// raw error, say — it is logged under `reference` and the channel gets
/// the reference instead. A research report is NOT this: its URLs are the
/// point, and it keeps going out through the floor only.
pub fn system_report(lines: &str, reference: Option<&str>) -> ChannelText {
    let mut out = scrub_system(lines.trim());
    if let Some(reference) = reference {
        out.push_str(&format!(
            "\nRef: {reference} (detail in the gateway log: `noo logs search {reference}`)"
        ));
    }
    ChannelText(scrub_internals(&out))
}

// ── Tier 2: error replies to a user's message ───────────────────────────

/// The general sentence a channel user gets when their request failed.
/// `what` is a short plain verb phrase ("record that decision", "answer
/// that"). The raw error is logged with the same reference id and does not
/// leave.
pub fn error_reply_text(what: &str, err: &dyn std::fmt::Display) -> ChannelText {
    let reference = new_ref();
    tracing::warn!(
        reference = %reference,
        what,
        error = %crate::redact::scrub(&err.to_string()),
        "channel_error_reply"
    );
    ChannelText(format!(
        "\u{26A0}\u{FE0F} I couldn't {what} \u{2014} reference `{reference}`."
    ))
}

/// [`error_reply_text`] as a plain `String`, for the ack paths that return
/// text to a caller that sends it (it passes the transport floor there).
pub fn error_reply(what: &str, err: &dyn std::fmt::Display) -> String {
    error_reply_text(what, err).into_string()
}

// ── Tier 3: the floor every transport applies ───────────────────────────

/// The floor: what every adapter transport sends. Masks only the internal
/// shapes ([`scrub_internals`]); ordinary text passes unchanged.
pub fn outbound(text: &str) -> ChannelText {
    ChannelText(scrub_internals(text))
}

// ── Scrubbers ───────────────────────────────────────────────────────────

fn re(p: &str) -> Regex {
    Regex::new(p).unwrap_or_else(|e| panic!("egress pattern {p}: {e}"))
}

/// Container-style names the operator types and reads in the CLI and
/// runbooks: systemd units and binaries, not stack DNS names. Everything
/// else shaped `noo-*` is a container name and is masked.
const OPERATOR_VOCAB_NOO_NAMES: &[&str] = &["noo-node-agent", "noo-hostd", "noo-cli"];

static PANIC: LazyLock<Regex> =
    LazyLock::new(|| re(r"thread '[^'\n]*' panicked at [^\n]*"));
static BACKTRACE: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)stack backtrace:.*"));
static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?-u:\b)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d{1,5})?(?-u:\b)")
});
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?(?::\d{1,5})?")
});
static TS_NET: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)(?-u:\b)(?:[a-z0-9-]+\.)+ts\.net(?::\d{1,5})?(?-u:\b)")
});
static NOO_NAME: LazyLock<Regex> = LazyLock::new(|| re(r"(?-u:\b)noo-[a-z0-9][a-z0-9-]*[a-z0-9](?::\d{1,5})?"));
static STACK_HOSTPORT: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)(?-u:\b)(?:localhost|gateway|postgres|redis|nats|loki|trellion(?:-intel)?|prometheus|grafana|alertmanager|vllm|llamacpp|ollama|tei):\d{2,5}(?-u:\b)")
});
static INTERNAL_PATH: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(^|[^\w.~/-])((?:/app|/opt/noo|/var/lib/noo[\w.-]*|/etc/noo[\w.-]*|/run/secrets|/tmp/noo[\w.-]*|~/\.noo[\w.-]*)(?:/[^\s`'"<>)\]]*)?)"#)
});
static NOO_ENV: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?-u:\b)(?:NOO|PAI)_[A-Z0-9_]*[A-Z0-9](?-u:\b)"));
static GO_NET: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?-u:\b)(?:dial|read|write) (?:tcp|udp)[46]?(?-u:\b)"));

// Tier-1-only (aggressive) shapes.
static URL: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?i)(?-u:\b)[a-z][a-z0-9+.-]*://[^\s`'"<>)\]]+"#));
static ANY_HOSTPORT: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?-u:\b)[A-Za-z][A-Za-z0-9_.-]*:\d{2,5}(?-u:\b)"));
static BARE_PORT: LazyLock<Regex> = LazyLock::new(|| re(r"(^|[\s(\[,])(:\d{2,5})(?-u:\b)"));
static ANY_PATH: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(^|[\s(`'"=\[])((?:~|\.{1,2})?/[\w.@-]+(?:/[\w.@-]*)+|[\w.-]+/[\w./-]*\.(?:rs|go|py|js|ts|toml|ya?ml|json|env|log|sock|pem|key|crt|conf)(?::\d+)*)"#)
});
static ANY_ENV: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?-u:\b)[A-Z][A-Z0-9]*_[A-Z0-9_]*[A-Z0-9](?-u:\b)"));

fn octets(c: &Captures) -> Option<[u16; 4]> {
    let mut o = [0u16; 4];
    for (i, slot) in o.iter_mut().enumerate() {
        let v: u16 = c.get(i + 1)?.as_str().parse().ok()?;
        if v > 255 {
            return None;
        }
        *slot = v;
    }
    Some(o)
}

/// Tailnet CGNAT (100.64.0.0/10, which holds the MagicDNS resolver
/// 100.100.100.100), the docker bridge range (172.16.0.0/12) and loopback.
/// A user's own 192.168.x / 10.x LAN is NOT internal to the platform and
/// passes — see the doc on false positives.
fn is_internal_v4(o: [u16; 4]) -> bool {
    (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || o[0] == 127
}

/// An IPv6 candidate is only an address if it is not a time of day: it
/// needs a `::` or a hex letter.
fn looks_like_v6(s: &str) -> bool {
    let core = s.trim_start_matches('[');
    core.matches(':').count() >= 2
        && (core.contains("::") || core.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')))
        && core.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 2
}

fn is_internal_v6(s: &str) -> bool {
    let core = s.trim_start_matches('[').to_ascii_lowercase();
    // The tailnet's ULA prefix, and loopback.
    core.starts_with("fd7a:115c:a1e0") || core == "::1" || core.starts_with("::1]")
}

/// Mask every balanced `{…}` JSON object whose opening matches `open`.
/// String-aware, so a `}` inside a value does not end the object early.
fn mask_json(s: &str, open: &Regex) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(m) = open.find(rest) {
        out.push_str(&rest[..m.start()]);
        let obj = &rest[m.start()..];
        let (mut depth, mut in_str, mut esc, mut end) = (0i32, false, false, obj.len());
        for (i, ch) in obj.char_indices() {
            if in_str {
                match (esc, ch) {
                    (true, _) => esc = false,
                    (false, '\\') => esc = true,
                    (false, '"') => in_str = false,
                    _ => {}
                }
                continue;
            }
            match ch {
                '"' => in_str = true,
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push_str(MASK);
        rest = &obj[end..];
    }
    out.push_str(rest);
    out
}

static JSON_ERROR_OPEN: LazyLock<Regex> = LazyLock::new(|| re(r#"\{\s*"error"\s*:"#));
static JSON_ANY_OPEN: LazyLock<Regex> = LazyLock::new(|| re(r#"\{\s*""#));

/// The floor (tier 3): mask ONLY the platform's internal shapes. Every
/// adapter transport applies this. Ordinary text — prose, code, public
/// URLs, a user's own LAN addresses, times of day — comes back unchanged.
pub fn scrub_internals(s: &str) -> String {
    // Credentials first: the shared shape table the log pipeline uses,
    // minus its two BARE guesses (`aws-secret`, `opaque-token`: a length
    // and an alphabet, nothing else). Here a person reads the text, and a
    // 40/43-character mixed-case identifier they asked about must come
    // back intact; every prefixed and structured shape (`noo-rt-…`,
    // `noo-sk-…`, a JWT, a PEM, a header) still runs. .
    let (secrets, _) = crate::redact::scrub_secrets_for_channel(s);
    let mut t = crate::redact::scrub(&secrets);

    t = PANIC.replace_all(&t, MASK).into_owned();
    t = BACKTRACE.replace_all(&t, MASK).into_owned();
    t = mask_json(&t, &JSON_ERROR_OPEN);
    t = TS_NET.replace_all(&t, MASK).into_owned();
    t = IPV4
        .replace_all(&t, |c: &Captures| match octets(c) {
            Some(o) if is_internal_v4(o) => MASK.to_string(),
            _ => c[0].to_string(),
        })
        .into_owned();
    t = IPV6
        .replace_all(&t, |c: &Captures| {
            if looks_like_v6(&c[0]) && is_internal_v6(&c[0]) {
                MASK.to_string()
            } else {
                c[0].to_string()
            }
        })
        .into_owned();
    t = INTERNAL_PATH.replace_all(&t, format!("${{1}}{MASK}").as_str()).into_owned();
    t = STACK_HOSTPORT.replace_all(&t, MASK).into_owned();
    t = NOO_NAME
        .replace_all(&t, |c: &Captures| {
            let m = &c[0];
            let name = m.split(':').next().unwrap_or(m);
            if OPERATOR_VOCAB_NOO_NAMES.contains(&name) && !m.contains(':') {
                m.to_string()
            } else {
                MASK.to_string()
            }
        })
        .into_owned();
    t = NOO_ENV.replace_all(&t, MASK).into_owned();
    t = GO_NET.replace_all(&t, MASK).into_owned();
    t
}

/// The aggressive scrubber (tier 1): for text the PLATFORM wrote, where
/// any address, URL, path, JSON body or setting name is by definition an
/// internal that slipped into a summary. Runs the floor, then masks every
/// remaining instance of those shapes, internal range or not.
pub fn scrub_system(s: &str) -> String {
    // Platform text names no user identifier, so the bare guesses the
    // floor skips (above) run here as they do on a log line.
    let (secrets, _) = crate::redact::scrub_secrets(s);
    let mut t = scrub_internals(&secrets);
    t = mask_json(&t, &JSON_ANY_OPEN);
    t = URL.replace_all(&t, MASK).into_owned();
    t = IPV4
        .replace_all(&t, |c: &Captures| match octets(c) {
            Some(_) => MASK.to_string(),
            None => c[0].to_string(),
        })
        .into_owned();
    t = IPV6
        .replace_all(&t, |c: &Captures| {
            if looks_like_v6(&c[0]) { MASK.to_string() } else { c[0].to_string() }
        })
        .into_owned();
    t = ANY_PATH.replace_all(&t, format!("${{1}}{MASK}").as_str()).into_owned();
    t = ANY_HOSTPORT.replace_all(&t, MASK).into_owned();
    t = BARE_PORT.replace_all(&t, format!("${{1}}{MASK}").as_str()).into_owned();
    t = ANY_ENV.replace_all(&t, MASK).into_owned();
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strings that must never reach a channel from ANY tier's output in
    /// this corpus — the brief's list, verbatim.
    const FORBIDDEN: &[&str] = &[
        "noo-vllm", "100.100.100.100", "172.18.", ":8000", "dial tcp", "{\"error\"",
        "/app/", "NOO_",
    ];

    fn assert_clean(label: &str, out: &str) {
        for f in FORBIDDEN {
            assert!(!out.contains(f), "{label}: `{f}` reached the channel text:\n{out}");
        }
    }

    /// The exact text the operator received in Google Chat on 2026-09-29.
    const REAL_GCHAT_ALERT: &str = "🔌 Backend `vllm` on `host3` is advertised in the mesh but refuses connections at its contract port ({\"error\":{\"code\":\"backend_unreachable\",\"message\":\"dial tcp: lookup noo-vllm on 100.100.100.100:53: no such host\",\"type\":\"node_agent_proxy_error\"}}). Its container healthcheck may still be green (image/env drift). Fix: recreate it with the pinned PORT env — `noo stack restart --force vllm` on host3 (dist-aware; raw compose is not), or re-provision the node.";

    /// Realistic raw errors, each stuffed into a summary the way a careless
    /// producer would (tier 1's defence in depth).
    const RAW_ERRORS: &[&str] = &[
        r#"{"error":{"code":"backend_unreachable","message":"dial tcp: lookup noo-vllm on 100.100.100.100:53: no such host","type":"node_agent_proxy_error"}}"#,
        "error sending request for url (https://100.64.0.12:8444/v1/chat/completions): client error (Connect): invalid peer certificate: UnknownIssuer; remote error: tls: unknown ca",
        "dial tcp 172.18.0.2:8000: connect: connection refused",
        "error returned from database: password authentication failed for user \"noo\" (postgres://noo:hunter2@noo-postgres:5432/noomesh)",
        "thread 'tokio-runtime-worker' panicked at /app/gateway-rust/src/routes/inference.rs:1068:5:\ncalled `Option::unwrap()` on a `None` value",
        "NOO_AGENT_ALERT_RECIPIENT is unset; read /app/config/noomesh.yaml",
        "connect to host3.tail1234.ts.net:8085 timed out",
    ];

    #[test]
    fn system_report_lines_are_tier1_and_the_ref_only_when_there_is_detail() {
        let lines = "Channel keepalive: telegram OK, google_chat OK\nnode host3.tail1234.ts.net:8085 at http://10.0.0.5:8444/x";
        let with = system_report(lines, Some("ref-abc")).into_string();
        assert!(with.starts_with("Channel keepalive: telegram OK, google_chat OK"), "{with}");
        assert!(with.contains("`noo logs search ref-abc`"), "{with}");
        // Tier 1: any URL, address or host:port in a platform-written line.
        for f in ["ts.net", "10.0.0.5", ":8444", "http://"] {
            assert!(!with.contains(f), "`{f}` reached the channel: {with}");
        }
        let without = system_report("Cluster Health: 3/3 nodes online", None).into_string();
        assert_eq!(without, "Cluster Health: 3/3 nodes online");
    }

    #[test]
    fn tier1_the_real_alert_carries_no_internals_even_if_passed_whole() {
        // Worst case: a producer hands the whole legacy string as the
        // summary. The scrubber alone must still clean it.
        let a = OperatorAlert::new("autonomy.backend_unreachable", "host3:vllm", REAL_GCHAT_ALERT)
            .investigate("noo cluster verify host3");
        let out = system(&a, "ref-0123456789");
        assert_clean("real alert", out.as_str());
        assert!(out.as_str().contains("host3"));
        assert!(out.as_str().contains("vllm"));
        assert!(out.as_str().contains("noo cluster verify host3"));
        assert!(out.as_str().contains("ref-0123456789"));
    }

    #[test]
    fn tier1_raw_errors_in_a_summary_are_all_masked() {
        for raw in RAW_ERRORS {
            let a = OperatorAlert::new("k", "host3:vllm", format!("Backend `vllm` on `host3` failed: {raw}"))
                .detail(*raw)
                .investigate("noo cluster verify host3");
            let out = system(&a, "ref-aaaaaaaaaa");
            assert_clean(raw, out.as_str());
            for f in ["hunter2", "100.64.0.12", "ts.net", "panicked", "inference.rs", "8444", "5432"] {
                assert!(!out.as_str().contains(f), "{f} leaked from {raw}:\n{out}");
            }
            assert!(out.as_str().contains("host3") && out.as_str().contains("vllm"));
            assert!(out.as_str().contains("noo cluster verify host3"));
        }
    }

    #[test]
    fn tier1_detail_is_never_rendered() {
        let a = OperatorAlert::new("k", "t", "Backend `vllm` on `host3` cannot be reached.")
            .detail("SENTINEL-DETAIL dial tcp 172.18.0.2:8000");
        let out = system(&a, "ref-bbbbbbbbbb");
        assert!(!out.as_str().contains("SENTINEL-DETAIL"));
    }

    #[test]
    fn tier1_rendering_shape_is_summary_command_reference() {
        let a = OperatorAlert::new("k", "t", "Node `host3` is down.").investigate("noo cluster verify host3");
        let out = system(&a, "ref-cccccccccc");
        let lines: Vec<&str> = out.as_str().lines().collect();
        assert_eq!(lines[0], "Node `host3` is down.");
        assert_eq!(lines[1], "Next: `noo cluster verify host3`");
        assert!(lines[2].starts_with("Ref: ref-cccccccccc"));
        assert!(lines[2].contains("noo logs search ref-cccccccccc"));
    }

    #[test]
    fn tier2_error_reply_is_general_and_carries_a_reference() {
        for raw in RAW_ERRORS {
            let out = error_reply_text("record that decision", raw);
            assert_clean(raw, out.as_str());
            assert!(out.as_str().starts_with("\u{26A0}\u{FE0F} I couldn't record that decision"));
            assert!(out.as_str().contains("`ref-"), "{out}");
        }
    }

    #[test]
    fn tier3_internals_in_an_assistant_answer_are_masked() {
        let answer = "The backend is at 172.18.0.5:8000 and the gateway dials noo-vllm; \
                      the tailnet name is host3.tail1234.ts.net, DNS is 100.100.100.100, \
                      config lives in /app/config/noomesh.yaml and NOO_LOKI_URL points at loki:3100. \
                      The error was {\"error\":{\"code\":\"x\"}} after dial tcp failed.";
        let out = outbound(answer);
        assert_clean("assistant", out.as_str());
        for f in ["ts.net", "loki:3100", "172.18.0.5"] {
            assert!(!out.as_str().contains(f), "{f}: {out}");
        }
        // The words around the masks survive.
        assert!(out.as_str().starts_with("The backend is at [internal]"));
    }

    #[test]
    fn tier3_ordinary_text_passes_through_unchanged() {
        for s in [
            "Here is the summary you asked for. Revenue grew 12% to $4.2M in Q3.",
            "Your router is at 192.168.1.1 and the printer at 10.0.0.42:631 — both on your LAN.",
            "See https://example.com/docs/setup and https://github.com/org/repo/pull/12.",
            "The meeting is at 14:30:00 tomorrow; bring the 2026-09-29 report.",
            "```rust\nfn main() { println!(\"{}\", 1 + 2); }\n```",
            "Run `noo cluster verify host3` and restart noo-node-agent if it is inactive.",
            "vllm is a serving engine; ollama and llama.cpp are alternatives.",
            "Set export PATH=$HOME/bin:$PATH in ~/.bashrc and open /etc/hosts.",
            "{\"name\": \"Ada\", \"role\": \"admin\"}",
            "Version 1.2.3.4 of the app shipped.",
            "The public resolver 1.1.1.1 and 8.8.8.8:53 are fine to mention.",
        ] {
            assert_eq!(outbound(s).as_str(), s, "ordinary text was rewritten");
        }
    }

    #[test]
    fn tier3_is_idempotent_on_its_own_output() {
        let once = outbound(REAL_GCHAT_ALERT).into_string();
        assert_eq!(outbound(&once).into_string(), once);
    }

    #[test]
    fn internal_ranges_are_exactly_the_documented_ones() {
        for ip in ["100.64.0.1", "100.100.100.100", "100.127.255.254", "172.16.0.1", "172.31.9.9", "127.0.0.1"] {  // leak-ok: CGNAT range-edge test, not a real node
            assert_eq!(scrub_internals(ip), MASK, "{ip} should be internal");
        }
        for ip in ["100.63.0.1", "100.128.0.1", "172.15.0.1", "172.32.0.1", "192.168.0.1", "10.1.2.3", "8.8.8.8"] {  // leak-ok: CGNAT range-edge test, not a real node
            assert_eq!(scrub_internals(ip), ip, "{ip} should pass");
        }
        assert_eq!(scrub_internals("fd7a:115c:a1e0::1"), MASK);
        assert_eq!(scrub_internals("2001:db8::1"), "2001:db8::1");
    }

    /// the reply path skips the two bare guesses and
    /// keeps every prefixed shape. Planted 2026-10-02: `scrub_internals`
    /// back on `scrub_secrets` → this fails on the identifier.
    #[test]
    fn a_43_char_identifier_in_a_reply_survives_but_a_prefixed_token_does_not() {
        // 43 base64url characters, an upper, a lower and a digit: exactly
        // what `opaque-token` takes in a log line.
        let ident = "RQm-sKtAHXH6SlzZSlXJp08TMyd2rkAZxb_EwgBRV_8";
        assert_eq!(ident.len(), 43);
        let reply = format!("Your build id is {ident}; paste it into the form.");
        assert_eq!(outbound(&reply).as_str(), reply, "a user-facing identifier was mangled");
        // A 40-character one (the `aws-secret` guess) survives too.
        let forty = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let reply40 = format!("The object key is {forty} in that bucket.");
        assert_eq!(outbound(&reply40).as_str(), reply40);
        // The same body behind its prefix is a refresh token, and goes.
        let tok = format!("noo-rt-{ident}");
        let out = outbound(&format!("Your session cookie was {tok}, keep it private.")).into_string();
        assert!(!out.contains(ident), "{out}");
        assert!(out.contains("<redacted:refresh-token>"), "{out}");
        // The log table still takes the bare guess.
        let (logged, n) = crate::redact::scrub_secrets(&reply);
        assert_eq!(n, 1, "{logged}");
        assert!(logged.contains("<redacted:opaque-token>"), "{logged}");
        // And so does tier 1, platform-written text.
        let sys = scrub_system(&reply);
        assert!(!sys.contains(ident), "{sys}");
    }

    #[test]
    fn secrets_are_masked_on_every_tier() {
        let s = "token noo-sk-ABCDEFGHIJKLMNOPQRSTUVWX and bot1234567890:AAFsomeSecretBodyHere-x";
        let out = outbound(s).into_string();
        assert!(!out.contains("ABCDEFGHIJKLMNOPQRSTUVWX"), "{out}");
        assert!(!out.contains("AAFsomeSecretBodyHere"), "{out}");
    }

    fn leaky(kind: &str, target: &str) -> OperatorAlert {
        OperatorAlert::new(kind, target, format!("Node '{target}' is offline."))
            .detail("dial 10.20.30.40:9100 failed: connection refused (os error 111) at https://internal.example.test/v1/probe?token=abc123")
            .investigate(format!("noo cluster verify {target}"))
    }

    const DETAIL_BITS: &[&str] = &["10.20.30.40", "https://", "internal.example.test", "os error 111", "connection refused", "abc123"];

    #[test]
    fn a_grouped_message_carries_summary_next_and_ref_never_detail() {
        let a = leaky("autonomy.node_health", "alpha");
        let b = leaky("autonomy.node_health", "beta");
        let out = system_group(&[(&a, "ref-aaaaaaaaaa", None), (&b, "ref-bbbbbbbbbb", None)]);
        let out = out.as_str();
        for bit in DETAIL_BITS {
            assert!(!out.contains(bit), "`{bit}` reached the grouped message:\n{out}");
        }
        for want in ["Node 'alpha' is offline.", "Node 'beta' is offline.", "Next: `noo cluster verify alpha`", "Next: `noo cluster verify beta`", "ref-aaaaaaaaaa", "ref-bbbbbbbbbb", "2 operator alerts"] {
            assert!(out.contains(want), "missing `{want}`:\n{out}");
        }
    }

    #[test]
    fn a_recovered_message_carries_duration_next_and_ref_never_detail() {
        let a = leaky("autonomy.node_health", "alpha");
        let out = system_recovered(&a, "ref-cccccccccc", 2 * 3600 + 300);
        let out = out.as_str();
        for bit in DETAIL_BITS {
            assert!(!out.contains(bit), "`{bit}` reached the recovered message:\n{out}");
        }
        assert!(out.contains("It lasted 2h 5m."), "{out}");
        assert!(out.contains("ref-cccccccccc"), "{out}");
        // And a recovery grouped with another alert is held to the same rule.
        let b = leaky("autonomy.node_health", "beta");
        let both = system_group(&[(&a, "ref-cccccccccc", Some(60)), (&b, "ref-dddddddddd", None)]);
        for bit in DETAIL_BITS {
            assert!(!both.as_str().contains(bit), "`{bit}` leaked in a mixed group");
        }
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(5), "5s");
        assert_eq!(human_duration(720), "12m");
        assert_eq!(human_duration(7500), "2h 5m");
        assert_eq!(human_duration(97_200), "1d 3h");
    }
}
