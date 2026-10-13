# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""What a node PUBLISHES and what its bus credential AUTHORISES must agree.

Three outages in one rail came from these two sides disagreeing, and every
one was silent:

  * gossip published bare `mesh.gossip.announce` while the credential granted
    `mesh.gossip.announce.{id}`. Every node with a per-principal credential
    went `unknown` and became undispatchable while still heartbeating.
  * `events.node.registered` and `events.ingest.doc.parsed` were published
    bare against scoped grants, so the 24h EVENTS history quietly stopped
    carrying them.
  * `users.conf` itself shipped a user line the server read literally.

NATS reports permission violations ASYNCHRONOUSLY. `Publish` returns nil,
nothing is logged, and the message never arrives — so no runtime test in this
repo can catch it: catching it needs a server that refuses, which CI has not
got. The disagreement is a source-level fact, so a source-level check is the
honest instrument rather than a second-best one.

BOTH DIRECTIONS, deliberately. A one-way "every published subject is granted"
would pass a credential full of authorisations nothing uses — privilege that
leaks quietly instead of failing loudly. The grant was in fact wrong both
ways at once: it authorised two scoped subjects nothing published, while what
was published got refused.

Static parse, same technique and for the same reason as
test_posture_key_parity.py: no NATS, no Go toolchain, no cargo on the
controller.

TWO PUBLISHERS hold the node credential since an earlier change: the Go node
agent, and the harness (`noo-gateway harness`, Rust) the agent places
beside the node's model. The harness publishes a turn's events on
`harness.turn.<node>.<conversation>` under the same principal, so its
literal prefix is read from `gateway-rust/src/websocket.rs` (`turn_subject`)
and compared against the `harness.turn.<id>.>` grant the same way the gossip
prefix is; its `harness.ready.<node>` start-up announcement (`tasks.rs`)
likewise. The node token comes first in the turn subject precisely so the
grant can be scoped to it.

SCOPE, stated so nobody reads more assurance into a green run than it earns:
this checks the node's PUBLISH subjects. The subscribe side and the `$JS.*`
JetStream API grants are not covered — a subject built from a variable cannot
be resolved statically, and the JetStream grants are derived from durable
consumer names rather than written at a call site.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "noo-cli/src/commands/nats_users.rs"
AGENT = ROOT / "node-agent-go"
HARNESS_SINK = ROOT / "gateway-rust/src/websocket.rs"
HARNESS_TASKS = ROOT / "gateway-rust/src/tasks.rs"

# The placeholder both sides use for the node id, so the comparison is about
# subject SHAPE rather than about any particular node.
ID = "{id}"


def _granted_publish_subjects() -> set[str]:
    """The Node role's publish allow-list, from `perms_for` in nats_users.rs."""
    src = RUST.read_text()
    node_arm = re.search(
        r"Role::Node\s*=>\s*format!\((.*?)\n\s*\),", src, re.S
    )
    assert node_arm, "the Role::Node arm of perms_for has changed shape"
    body = node_arm.group(1)
    allow = re.search(r"publish:.*?allow:\s*\[(.*?)\]", body, re.S)
    assert allow, "no publish allow-list in the Role::Node arm"
    subjects = re.findall(r'\\"([^"\\]+)\\"', allow.group(1))
    assert subjects, "parsed an empty publish allow-list — the escaping changed"
    # JetStream API grants are derived from durable consumer names, not from
    # a publish call site, so they are out of this test's scope.
    return {s for s in subjects if not s.startswith("$JS")}


def _go_sources() -> list[Path]:
    return [
        p
        for p in AGENT.rglob("*.go")
        if not p.name.endswith("_test.go")
    ]


def _published_subjects() -> dict[str, str]:
    """Subject shape -> where it is published, from the agent's source.

    Only literals are resolvable. A subject assembled from a variable is
    invisible here, which is why the two scoping helpers are matched by NAME:
    every event a node emits is required to go through one of them (the Go
    source-scan guard in internal/messaging enforces that separately), and
    each appends the node id.
    """
    found: dict[str, str] = {}
    for path in _go_sources():
        rel = path.relative_to(ROOT)
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            where = f"{rel}:{lineno}"
            if m := re.search(r'PublishNodeEvent\("([^"]+)"', line):
                found[f"events.{m.group(1)}.{ID}"] = where
            elif m := re.search(r'PublishJobEvent\("([^"]+)"', line):
                found[f"events.job.{m.group(1)}.{ID}"] = where
            elif m := re.search(r'\bPublish\("([^"]+)"', line):
                # A bare literal handed straight to Publish. This is the
                # shape the gossip bug had, and it must be visible here.
                found[m.group(1)] = where
    # Built by gossipAnnounceSubject, whose literal prefix is what the grant
    # has to match. Read the prefix rather than hardcoding it, so renaming
    # the subject fails this test instead of quietly passing it.
    mesh = (AGENT / "internal/messaging/mesh.go").read_text()
    m = re.search(r'func gossipAnnounceSubject\([^)]*\)\s*string\s*\{\s*return\s+"([^"]+)"\s*\+', mesh)
    assert m, "gossipAnnounceSubject no longer returns a literal prefix + id"
    found[f"{m.group(1)}{ID}"] = "node-agent-go/internal/messaging/mesh.go"
    # The harness publishes under the node credential from the
    # gateway binary: `turn_subject` is a literal prefix, then the NODE id,
    # then the conversation. The grant is written against the node token —
    # `harness.turn.<id>.>` — so read the prefix and assert the node comes
    # first; a subject that put the conversation first would pass a naive
    # prefix check and be fleet-wide again.
    sink = HARNESS_SINK.read_text()
    m = re.search(
        r'pub fn turn_subject\(node: &str, conversation_id: &str\)\s*->\s*String\s*\{\s*'
        r'format!\("([^"{]+)\{\}\.\{\}",\s*subject_token\(node\)',
        sink,
    )
    assert m, "turn_subject no longer builds prefix + node + conversation, node first"
    found[f"{m.group(1)}{ID}.>"] = "gateway-rust/src/websocket.rs"
    # And its start-up announcement: a literal prefix plus the
    # node id, matched to a scoped grant like the gossip announce.
    tasks = HARNESS_TASKS.read_text()
    m = re.search(r'pub fn ready_subject\([^)]*\)\s*->\s*String\s*\{\s*format!\("([^"{]+)\{', tasks)
    assert m, "ready_subject no longer builds a literal prefix + node id"
    found[f"{m.group(1)}{ID}"] = "gateway-rust/src/tasks.rs"
    return found


def test_every_published_subject_is_granted() -> None:
    """The outage direction: publishing something the credential refuses."""
    granted = _granted_publish_subjects()
    published = _published_subjects()
    ungranted = {s: w for s, w in published.items() if s not in granted}
    assert not ungranted, (
        "these subjects are published by the node agent but NOT authorised by "
        "its per-principal credential. NATS refuses them asynchronously, so "
        "the publish appears to succeed and the message never arrives:\n  "
        + "\n  ".join(f"{s}   ({w})" for s, w in sorted(ungranted.items()))
        + f"\n\ngranted: {sorted(granted)}"
    )


def test_every_granted_subject_is_published() -> None:
    """The leak direction: authorising something nothing uses.

    A grant is a privilege. One that no call site needs is privilege handed
    to every node for nothing, and unlike the other direction it never
    announces itself — the fleet works perfectly with it.
    """
    granted = _granted_publish_subjects()
    published = set(_published_subjects())
    unused = granted - published
    assert not unused, (
        "the node credential authorises subjects nothing publishes — remove "
        "them from perms_for, or the grant is wider than the code needs:\n  "
        + "\n  ".join(sorted(unused))
        + f"\n\npublished: {sorted(published)}"
    )


def test_the_parse_actually_found_both_sides() -> None:
    """Guard the guard.

    Both assertions above compare sets, and two empty sets agree perfectly.
    A regex that stops matching would turn this file into a test that passes
    while checking nothing — which is the failure mode it exists to prevent.
    """
    granted = _granted_publish_subjects()
    published = _published_subjects()
    assert len(granted) >= 6, f"only parsed {len(granted)} grants: {sorted(granted)}"
    assert len(published) >= 6, f"only parsed {len(published)} publishes: {sorted(published)}"
    assert any(s.startswith("mesh.gossip.announce") for s in published)
    assert any(s.startswith("events.job.") for s in published)


# ---------------------------------------------------------------------------
# The two things the docstring above declares out of scope — because both of
# them are exactly what broke next (#1218).
#
# The scope note said the JetStream grants are "derived from durable consumer
# names rather than written at a call site", and treated that as a reason not
# to check them. But a durable consumer name IS a call site: it is a literal
# format string in executor.go, and the client library turns it into subjects
# by a documented rule. The same goes for the inbox prefix. Neither needs a
# running server to check, only the honesty to read what the client sends.
#
# What #1218 cost: every node holding a per-principal credential failed to
# bind its dispatch consumer, kept heartbeating, showed Online, and ran no
# jobs. Two spellings, in two languages, with nothing comparing them.
# ---------------------------------------------------------------------------

EXECUTOR = AGENT / "internal/jobs/executor.go"
NATS_GO = AGENT / "internal/messaging/nats.go"


def _node_arm() -> str:
    src = RUST.read_text()
    arm = re.search(r"Role::Node\s*=>\s*format!\((.*?)\n\s*\),", src, re.S)
    assert arm, "the Role::Node arm of perms_for has changed shape"
    return arm.group(1)


def _list(section: str, field: str) -> list[str]:
    body = _node_arm()
    block = re.search(rf"{section}:.*?{field}:\s*\[(.*?)\]", body, re.S)
    assert block, f"no {field} list in the Node arm's {section} block"
    out = re.findall(r'\\"([^"\\]+)\\"', block.group(1))
    assert out, f"parsed an empty {section}/{field} list — the escaping changed"
    return out


def _subject_matches(pattern: str, subject: str) -> bool:
    """NATS subject matching: `*` is one token, `>` is one-or-more tokens."""
    p, s = pattern.split("."), subject.split(".")
    for i, tok in enumerate(p):
        if tok == ">":
            return len(s) > i
        if i >= len(s):
            return False
        if tok != "*" and tok != s[i]:
            return False
    return len(s) == len(p)


def test_the_node_inbox_prefix_matches_the_agents() -> None:
    """The agent sets a custom inbox prefix; the grant must be the same string.

    The grant said `_INBOX_node-<id>` and the agent uses `_INBOX_node_<id>`.
    A reply inbox the node cannot subscribe to makes every request/reply it
    issues time out — including the consumer-create that binds dispatch.
    """
    m = re.search(
        r'func NodeInboxPrefix\([^)]*\)\s*string\s*\{\s*return\s+"([^"]+)"\s*\+',
        NATS_GO.read_text(),
    )
    assert m, "NodeInboxPrefix no longer returns a literal prefix + token"
    prefix = m.group(1)  # "_INBOX_node_"
    allowed = _list("subscribe", "allow")
    assert any(a.startswith(prefix) for a in allowed), (
        f"the agent subscribes under {prefix!r} (nats.go CustomInboxPrefix) but "
        f"the node credential grants none of it: {allowed}"
    )


def test_the_jetstream_grants_cover_the_durables_the_agent_binds() -> None:
    """Every durable the executor creates, with the verbs js.Subscribe sends.

    `js.Subscribe` with a durable issues STREAM.NAMES (to resolve the stream
    for the subject), CONSUMER.INFO, then CONSUMER.CREATE — and since nats.go
    on a server >= 2.9 appends the filter subject to the create subject, the
    grant has to end in `>` past the consumer name.
    """
    src = EXECUTOR.read_text()
    durables = re.findall(r'durable\s*:?=\s*fmt\.Sprintf\("([^"]+)"', src, re.I)
    assert durables, "no durable consumer names found in executor.go"
    shapes = {d.replace("%s", ID) for d in durables}
    assert len(shapes) >= 2, f"expected the dispatch and cancel durables: {shapes}"

    granted = set(_list("publish", "allow"))
    assert "$JS.API.STREAM.NAMES" in granted, (
        "js.Subscribe resolves the stream for a subject with $JS.API.STREAM.NAMES "
        "before anything else; without it the consumer never binds"
    )
    for shape in shapes:
        stream = "TASKS" if "dispatch" in shape else "EVENTS"
        needed = [
            f"$JS.API.CONSUMER.INFO.{stream}.{shape}",
            f"$JS.API.CONSUMER.CREATE.{stream}.{shape}.>",
            f"$JS.ACK.{stream}.{shape}.>",
        ]
        missing = [n for n in needed if n not in granted]
        assert not missing, (
            f"the agent binds durable {shape!r} on {stream}, but its credential "
            f"is missing:\n  " + "\n  ".join(missing)
        )


def test_no_deny_rule_swallows_a_granted_subject() -> None:
    """Deny wins over allow, so a broad deny silently voids a narrow allow.

    This is why adding $JS.API.STREAM.NAMES to the allow-list alone did not
    fix #1218: the deny list still carried $JS.API.STREAM.> and beat it. A
    rule that can never take effect reads, to anyone auditing the file, as a
    permission the node has.
    """
    for section in ("publish", "subscribe"):
        allow, deny = _list(section, "allow"), _list(section, "deny")
        for a in allow:
            concrete = a.rstrip(">").rstrip(".") if a.endswith(">") else a
            swallowed = [d for d in deny if _subject_matches(d, concrete)]
            assert not swallowed, (
                f"the node's {section} grant {a!r} can never take effect — "
                f"it is denied by {swallowed}. Deny wins over allow in NATS."
            )


# ── the CONTROLLER principals ────────────────────────────────────────────
#
# The node is not the only principal whose grant can drift away from its
# call sites. `worker` is held by noo-worker, noo-trellion and
# noo-trellion-intel, and its publish allow-list is narrow for the same
# reason the node's is: it is denied `tasks.>`, `$KV.>` and stream
# administration, so a subject it publishes and is not granted disappears
# exactly as silently.
#
# Scope, stated honestly: the Python side publishes almost everything
# through one helper (`ClusterMessaging.publish_event`, which prefixes
# `events.`), and only its LITERAL call sites are resolvable statically.
# That is enough to have caught the one real drift there is to catch —
# `events.backend.started`, which the helper's own docstring holds up as
# the example and which the grant does not cover.

WORKER_PY = ROOT / "src/noomesh"


def _worker_publish_grant() -> set[str]:
    """The Worker role's publish allow-list, from `perms_for`."""
    src = RUST.read_text()
    arm = re.search(r"Role::Worker\s*=>\s*format!\((.*?)\n\s*\),", src, re.S)
    assert arm, "the Role::Worker arm of perms_for has changed shape"
    allow = re.search(r"publish:.*?allow:\s*\[(.*?)\]", arm.group(1), re.S)
    assert allow, "no publish allow-list in the Role::Worker arm"
    subjects = re.findall(r'\\"([^"\\]+)\\"', allow.group(1))
    assert subjects, "parsed an empty publish allow-list — the escaping changed"
    return set(subjects)


def _grant_covers(grant: set[str], subject: str) -> bool:
    """NATS subject matching, for the token wildcards the grants use."""
    for pattern in grant:
        p, s = pattern.split("."), subject.split(".")
        if p and p[-1] == ">":
            if len(s) >= len(p) - 1 and all(
                a == b or a == "*" for a, b in zip(p[:-1], s)
            ):
                return True
            continue
        if len(p) == len(s) and all(a == b or a == "*" for a, b in zip(p, s)):
            return True
    return False


def _worker_published_subjects() -> dict[str, str]:
    """`events.<type>` for every literal `publish_event(...)` call site.

    Docstrings are excluded on purpose: the helper's example is not a call.
    A line inside a triple-quoted block is skipped by tracking fence parity,
    which is crude but sufficient for the one file that matters.
    """
    found: dict[str, str] = {}
    for path in sorted(WORKER_PY.rglob("*.py")):
        rel = path.relative_to(ROOT)
        in_doc = False
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            fences = line.count('"""') + line.count("'''")
            was_in_doc = in_doc
            if fences % 2 == 1:
                in_doc = not in_doc
            if was_in_doc or in_doc:
                continue
            m = re.search(r'publish_event\(\s*"([^"]+)"', line)
            if m:
                found[f"events.{m.group(1)}"] = f"{rel}:{lineno}"
    return found


def test_the_parser_finds_the_worker_grant_and_its_call_sites():
    """The guard has to be capable of finding something.

    Both halves of the comparison below are parsed out of source. A regex
    that silently matched nothing would make the real test pass on any
    code at all — the repo's own anti-pattern.
    """
    grant = _worker_publish_grant()
    assert "worker.>" not in grant, (
        "worker.> is the SUBSCRIBE side; if it appears in the publish "
        "allow-list the arm has been restructured and this test is reading "
        "the wrong list"
    )
    assert any(g.startswith("events.") for g in grant), grant
    assert _worker_published_subjects(), (
        "found no publish_event call site — the parser has gone blind"
    )


def test_every_subject_the_worker_publishes_is_granted():
    grant = _worker_publish_grant()
    ungranted = {
        subject: where
        for subject, where in _worker_published_subjects().items()
        if not _grant_covers(grant, subject)
    }
    assert not ungranted, (
        "the worker principal publishes subject(s) its NATS credential does "
        "not authorise. NATS drops a denied publish and tells the client "
        "NOTHING, so this does not fail at runtime — the message simply "
        f"never arrives:\n  {ungranted}\n  grant: {sorted(grant)}"
    )


def test_the_matcher_understands_the_wildcards_the_grants_use():
    """...because the test above is only as good as this function."""
    g = {"events.cluster.*", "events.job.cancel", "agent.msg.>"}
    assert _grant_covers(g, "events.cluster.up")
    assert _grant_covers(g, "events.job.cancel")
    assert _grant_covers(g, "agent.msg.direct.bob")
    assert not _grant_covers(g, "events.cluster.up.extra")   # * is ONE token
    assert not _grant_covers(g, "events.backend.started")
    assert not _grant_covers(g, "tasks.dispatch")


def test_only_the_gateway_principal_holds_the_whole_bus():
    """`>` is the credential isolation exists to stop being handed out.

    `gateway` legitimately holds it — it is the JetStream administrator and
    the only KV writer. (`Legacy` held it too, as the old shared credential,
    until an earlier change retired that principal.) Anything else acquiring it
    would make that principal's whole permission block decorative, which is
    tracker N8 in miniature.
    """
    src = RUST.read_text()
    arms = re.findall(
        r"Role::(\w+(?:\s*\|\s*Role::\w+)*)\s*=>\s*format!\((.*?)\n\s*\),",
        src,
        re.S,
    )
    assert arms, "perms_for has changed shape"
    wide = {
        name.strip()
        for names, body in arms
        for name in names.replace("Role::", "").split("|")
        if '\\"' + ">" + '\\"' in body and "allow:" in body
        and re.search(r'allow:\s*\[\\">\\"\]', body)
    }
    assert wide == {"Gateway"}, (
        f"principals granted `>`: {wide or 'none'} — expected exactly Gateway"
    )
