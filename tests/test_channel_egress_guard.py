# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every channel send passes through the egress boundary (gateway-rust
src/egress.rs).

A channel (Google Chat, Telegram, WhatsApp) is outside the trust boundary.
On 2026-09-29 an operator alert reached Google Chat carrying a container
name, the MagicDNS resolver's address, a Go dial error and a raw JSON body.
The fix is one boundary with three tiers; this guard holds the WIRING, so a
new sender cannot quietly go around it:

1. Every adapter transport in routes/communication.rs runs its text through
   ``crate::egress::outbound`` before it posts (the floor — tier 3 — which
   tiers 1 and 2 pass through too).
2. No other Rust file builds a channel-API send URL, so there is no second
   transport to forget.
3. The operator-alert funnel only hands ``ChannelText`` to the wire, and
   ``ChannelText`` is only constructed inside egress.rs (tier 1). Every
   producer builds an ``OperatorAlert`` — the sentence API
   (``send_operator_alert(…, &str)``) is gone and may not come back — with
   one ``.investigate(…)`` command and no raw evidence in its summary
. System heartbeat reports render through tier 1 too.
4. Channel handlers never interpolate an error into reply text with
   ``format!`` (tier 2: ``egress::error_reply`` or ``anyhow!`` for the log).
5. Python has no transport of its own: no channel-API URL, and every POST
   to ``/api/channels/send`` (which lands on the Rust transports) sits in a
   known file.

Each check asserts it found what it inspects, so a rename cannot turn it
into a guard of nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RS = ROOT / "gateway-rust" / "src"
COMM = RS / "routes" / "communication.rs"
EGRESS = RS / "egress.rs"
ALERT = RS / "operator_alert.rs"

TRANSPORTS = ("send_whatsapp", "send_telegram", "send_google_chat", "send_telegram_keyboard")

# A send URL for each adapter API, as the Rust source spells it.
CHANNEL_API_SEND = re.compile(
    r"api\.telegram\.org/bot\{[^}]*\}/sendMessage"
    r"|chat\.googleapis\.com/v1/\{[^}]*\}/messages"
    r"|graph\.facebook\.com/[^\"]*/messages"
)


def _block_end(src: str, start: int) -> int:
    """Index just past the `}` matching the `{` at `start`. Skips string,
    raw-string and char literals and `//` comments, so a brace in a format
    string does not end the block early."""
    i, depth, n = start, 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i == -1 else i
            continue
        m = re.match(r'r(#*)"', src[i:]) if c == "r" and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")) else None
        if m:
            close = '"' + m.group(1)
            j = src.find(close, i + len(m.group(0)))
            i = n if j == -1 else j + len(close)
            continue
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
            i += 1
            continue
        if c == "'":
            m = re.match(r"'(?:\\.|[^\\'])'", src[i:])
            if m:
                i += len(m.group(0))
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError("unbalanced braces")


def _strip_tests(src: str) -> str:
    """Drop `#[cfg(test)] mod … { … }` blocks and comment lines — test
    strings and prose are not senders. Only whole test MODULES are dropped:
    cutting at the first `#[cfg(test)]` would hide everything after a
    test-only helper in the middle of a file."""
    out, pos = [], 0
    for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", src):
        if m.start() < pos:
            continue
        out.append(src[pos : m.start()])
        pos = _block_end(src, m.end() - 1)
        # Keep the line count, so a reported line number is the real one.
        out.append("\n" * src[m.start() : pos].count("\n"))
    out.append(src[pos:])
    src = "".join(out)
    return "\n".join("" if line.lstrip().startswith("//") else line for line in src.splitlines())


def fn_body(src: str, name: str) -> str:
    """The body of `fn name(`, brace-matched from its first `{`."""
    m = re.search(rf"\bfn {re.escape(name)}\s*[<(]", src)
    assert m, f"fn {name} not found — this guard is reading the wrong file"
    start = src.index("{", src.index(")", m.end()))
    depth = 0
    for i in range(start, len(src)):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
    raise AssertionError(f"unbalanced body for fn {name}")


def test_every_transport_applies_the_egress_floor_before_posting():
    src = COMM.read_text()
    checked = 0
    for name in TRANSPORTS:
        body = fn_body(src, name)
        post = body.find(".post(")
        assert post != -1, f"{name} no longer posts — update TRANSPORTS"
        floor = body.find("crate::egress::outbound(")
        assert floor != -1 and floor < post, (
            f"{name} sends to a channel without crate::egress::outbound — "
            "every byte leaving through an adapter must pass the floor"
        )
        # The text it posts must be the floored one: the raw parameter
        # `message` must not be read again after the floor rebinds it.
        after = body[floor:]
        assert "let message = crate::egress::outbound(message)" in body, (
            f"{name}: the floor must rebind `message` so the raw text is unreachable"
        )
        assert "split_message(message," not in after, (
            f"{name}: splits the RAW message, not the floored one"
        )
        checked += 1
    assert checked == len(TRANSPORTS) >= 4


def test_no_other_rust_file_builds_a_channel_send_url():
    hits: dict[str, list[str]] = {}
    for p in RS.rglob("*.rs"):
        src = _strip_tests(p.read_text())
        found = CHANNEL_API_SEND.findall(src)
        if found:
            hits[str(p.relative_to(RS))] = found
    # Vacuity: the transports themselves must be found by the pattern.
    assert "routes/communication.rs" in hits, "pattern no longer matches the real transports"
    assert len(hits["routes/communication.rs"]) >= 4, hits
    others = {k: v for k, v in hits.items() if k != "routes/communication.rs"}
    assert not others, (
        f"channel API send URL built outside routes/communication.rs: {others}. "
        "Add a transport there (it gets the egress floor) and call it instead."
    )


def test_operator_alerts_only_hand_channel_text_to_the_wire():
    src = ALERT.read_text()
    assert re.search(r"pub async fn dispatch_raw\(message: &ChannelText\)", src), (
        "dispatch_raw must take &ChannelText — the type is the tier-1 boundary"
    )
    # In process since the ChannelText goes straight to the
    # adapter, not into a self-call body.
    assert "message.as_str()" in fn_body(src, "dispatch_raw")
    funnels = ("send_operator_alert_with", "send_operator_alert_detached_with")
    # The detached entry point delegates to the funnel (delivery is deferred
    # to the group window for both), so it renders only through it.
    assert "egress::system(" in fn_body(src, "send_operator_alert_with")
    assert "send_operator_alert_with(" in fn_body(src, "send_operator_alert_detached_with")
    assert "egress::system_group(" in src
    # ChannelText is only minted in egress.rs.
    minted = []
    for p in RS.rglob("*.rs"):
        if p == EGRESS:
            continue
        if re.search(r"\bChannelText\(", _strip_tests(p.read_text())):
            minted.append(str(p.relative_to(RS)))
    assert not minted, f"ChannelText constructed outside egress.rs: {minted}"
    assert "ChannelText(" in EGRESS.read_text()


def test_every_alert_producer_goes_through_the_funnel():
    """A producer reaches a channel only via operator_alert's funnels — no
    one calls dispatch_raw directly."""
    producers = 0
    direct = []
    for p in RS.rglob("*.rs"):
        if p in (ALERT,):
            continue
        src = _strip_tests(p.read_text())
        producers += len(re.findall(r"operator_alert::send_operator_alert", src))
        if re.search(r"operator_alert::dispatch_raw\(", src):
            direct.append(str(p.relative_to(RS)))
    assert producers >= 40, f"only {producers} alert producers found — guard is reading the wrong tree"
    assert not direct, f"dispatch_raw called outside the funnel: {direct}"


# The sentence-shaped entry points that were retired. Any of
# these names followed by `(` — a definition or a call — is a producer
# handing a channel a sentence instead of an OperatorAlert.
LEGACY_SENTENCE_API = re.compile(r"\bsend_operator_alert(?:_detached)?\s*\(")


def test_the_sentence_alert_api_is_gone():
    """No `send_operator_alert(state, kind, target, cooldown, &str)` and no
    `send_operator_alert_detached(…, String)`: every producer builds an
    OperatorAlert (summary + one command + detail). A new caller that
    passes a sentence fails here, and so does bringing the function back."""
    offenders = []
    funnels = 0
    for p in RS.rglob("*.rs"):
        src = _strip_tests(p.read_text())
        for n, line in enumerate(src.splitlines(), 1):
            if LEGACY_SENTENCE_API.search(line):
                offenders.append(f"{p.relative_to(RS)}:{n}: {line.strip()}")
        funnels += len(re.findall(r"\bsend_operator_alert(?:_detached)?_with\s*\(", src))
    # Vacuity: the structured funnels are where the producers went.
    assert funnels >= 45, f"only {funnels} structured alert calls found — guard is reading the wrong tree"
    assert not offenders, (
        "sentence-shaped operator alert — build a crate::operator_alert::OperatorAlert "
        "(general summary, .investigate(\"noo …\"), evidence in .detail) and call "
        "send_operator_alert_with / send_operator_alert_detached_with:\n" + "\n".join(offenders)
    )


def _call_end(src: str, open_paren: int) -> int:
    """Index just past the `)` matching the `(` at `open_paren`; string- and
    char-literal aware, like _block_end."""
    i, depth, n = open_paren, 0, len(src)
    while i < n:
        c = src[i]
        m = re.match(r'r(#*)"', src[i:]) if c == "r" and not (src[i - 1].isalnum() or src[i - 1] == "_") else None
        if m:
            close = '"' + m.group(1)
            j = src.find(close, i + len(m.group(0)))
            i = n if j == -1 else j + len(close)
            continue
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
            i += 1
            continue
        if c == "'":
            m = re.match(r"'(?:\\.|[^\\'])'", src[i:])
            if m:
                i += len(m.group(0))
                continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError("unbalanced parens")


def _alert_constructions():
    """(file, line, args, chain) for every `OperatorAlert::new(…)` outside
    tests and egress.rs: its argument text and the `.method(…)` builder
    chain that follows it."""
    out = []
    for p in RS.rglob("*.rs"):
        if p == EGRESS:
            continue
        src = _strip_tests(p.read_text())
        for m in re.finditer(r"OperatorAlert::new\s*\(", src):
            end = _call_end(src, m.end() - 1)
            args = src[m.end() : end - 1]
            j = end
            while True:
                mm = re.match(r"\s*\.(\w+)\s*\(", src[j:])
                if not mm:
                    break
                j = _call_end(src, j + mm.end() - 1)
            out.append((str(p.relative_to(RS)), src[: m.start()].count("\n") + 1, args, src[end:j]))
    return out


def test_every_operator_alert_names_one_investigation_command():
    """The channel gets a summary, a `Next:` command and a reference. An
    alert without `.investigate(…)` hands the operator a symptom and a log
    id and nothing to type."""
    alerts = _alert_constructions()
    assert len(alerts) >= 45, f"only {len(alerts)} OperatorAlert constructions found"
    missing = [f"{f}:{n}" for f, n, _, chain in alerts if ".investigate(" not in chain]
    assert not missing, (
        "OperatorAlert without an investigation command — add "
        ".investigate(\"noo …\") (a command `noo` accepts; the CLI hint lint checks it): "
        + ", ".join(missing)
    )


# Placeholders that carry raw evidence. In an alert they belong in
# `.detail(…)`, which is logged; the summary is rendered for a channel.
EVIDENCE_PLACEHOLDER = re.compile(r"\{(?:e|err|error|detail|body|resp|response|why_raw|raw)(?::[^}]*)?\}")


def test_alert_summaries_do_not_interpolate_evidence():
    """The summary (OperatorAlert::new's third argument) is what a channel
    reads. An error interpolated there is caught today only by the
    scrubber; the rule is that it goes in `.detail`."""
    offenders = []
    for f, n, args, _ in _alert_constructions():
        if EVIDENCE_PLACEHOLDER.search(args) or re.search(r"\be(?:rr)?\.to_string\(\)", args):
            offenders.append(f"{f}:{n}")
    assert not offenders, (
        "raw evidence interpolated into an alert SUMMARY — move it to .detail(…): " + ", ".join(offenders)
    )


def test_system_heartbeat_reports_render_through_tier_one():
    """cluster_health / security_audit / channel_keepalive are platform-
    authored: they return a SystemReport (general lines + detail) and
    notify_channels renders the lines with egress::system_report — not
    the floor-only content path a research report takes."""
    ha = (RS / "heartbeat_actions.rs").read_text()
    for action in ("action_cluster_health", "action_security_audit", "action_channel_keepalive"):
        m = re.search(rf"async fn {action}\([^)]*\)\s*->\s*Result<(\w+)", ha)
        assert m, f"{action} not found — this guard is reading the wrong file"
        assert m.group(1) == "SystemReport", f"{action} returns {m.group(1)}, not a structured SystemReport"
    body = fn_body(ha, "notify_channels")
    sys_at = body.find("crate::egress::system_report(")
    assert sys_at != -1, "notify_channels does not render system reports through egress::system_report"
    # …and does so before the content path (quality gate / attachment) runs.
    assert sys_at < body.find("classify_response_quality"), "system reports must branch off before the content path"
    # Both run paths hand the structured lines through.
    for f in ("heartbeat_loop.rs", "routes/intelligence.rs"):
        assert "native_system" in (RS / f).read_text(), f"{f} drops the SystemReport lines"


def test_a_node_cannot_author_the_failover_alert_text():
    """The harness rail carries a node's alert as evidence only: the gateway
    rebuilds the summary and command from its own copy."""
    harness = _strip_tests((RS / "routes" / "harness.rs").read_text())
    arm = harness[harness.index("HarnessOp::OperatorAlert {") :]
    arm = arm[: arm.index("json!({})")]
    assert "backend_failover_alert(" in arm, "the rail's alert arm must re-author the alert"


def test_channel_handlers_never_format_an_error_into_a_reply():
    files = sorted((RS / "channels").glob("*.rs"))
    assert len(files) >= 5, files
    offenders = []
    for p in files:
        for n, line in enumerate(_strip_tests(p.read_text()).splitlines(), 1):
            if re.search(r"\{(?:e|err|error)(?::[^}]*)?\}", line) and "format!(" in line:
                offenders.append(f"{p.name}:{n}: {line.strip()}")
    assert not offenders, (
        "an error interpolated into text in a channel handler — a reply must use "
        "crate::egress::error_reply (tier 2); anyhow!/tracing carry it to the log:\n"
        + "\n".join(offenders)
    )
    # And the tier-2 helper is actually in use there.
    uses = sum(p.read_text().count("egress::error_reply") for p in files)
    assert uses >= 5, f"egress::error_reply used {uses}x in channels/ — expected >= 5"


PY_ROOTS = [ROOT / "src", ROOT / "packages", ROOT / "plugins"]
PY_CHANNEL_API = re.compile(
    r"api\.telegram\.org|chat\.googleapis\.com|graph\.facebook\.com|\bsmtplib\b"
)
# The Python files allowed to POST /api/channels/send (the gateway route,
# which reaches the Rust transports and their floor).
PY_SEND_DOORS = {
    "src/noomesh/channels/gateway_client.py",
}


def _py_files():
    for root in PY_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*.py"):
            rel = p.relative_to(ROOT).as_posix()
            if "/tests/" in rel or "/legacy/" in rel:
                continue
            yield rel, p


def test_python_has_no_channel_transport_of_its_own():
    scanned = 0
    direct, doors = [], set()
    for rel, p in _py_files():
        scanned += 1
        src = p.read_text(errors="replace")
        code = "\n".join(
            line for line in src.splitlines() if not line.lstrip().startswith("#")
        )
        if PY_CHANNEL_API.search(code):
            direct.append(rel)
        if re.search(r"\.post\(\s*f?[\"'][^\"']*/api/channels/send", code, re.S):
            doors.add(rel)
    assert scanned > 100, f"only {scanned} Python files scanned"
    assert not direct, (
        f"Python reaches a channel API directly: {direct}. Send through "
        "ChannelManager.dispatch / GatewayChannelClient (POST /api/channels/send) "
        "so the Rust egress floor applies."
    )
    assert "src/noomesh/channels/gateway_client.py" in doors, "the Python door moved — update PY_SEND_DOORS"
    assert doors <= PY_SEND_DOORS, f"new Python POST to /api/channels/send: {doors - PY_SEND_DOORS}"
