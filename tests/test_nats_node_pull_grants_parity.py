# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The node's JetStream grants for PULLED embed work must match the worker.

Companion to test_nats_node_subject_parity.py, which says in its SCOPE note
that the `$JS.*` grants are not covered. This covers the ones i179 adds.

A node that PULLS from stream WORK_EMBED sends, via nats.go v1.54.0
`PullSubscribe(subj, durable, nats.Bind(stream, consumer))` then `Fetch`:

  * CONSUMER.INFO.<stream>.<consumer>   (js.go:1825 -> 3673)
  * CONSUMER.MSG.NEXT.<stream>.<consumer> (js.go:1902, published at 3285)
  * the `$JS.ACK.<stream>.<consumer>.…` reply of each message (js.go:3801)

and NOTHING else: Bind skips `STREAM.NAMES` (js.go:1813-1815, stream is given) and
the create branch (js.go:1859, not taken when `consumerBound`). A denied INFO
times out, which js.go:1840-1843 TOLERATES for a bound pull consumer, so even
that failure is silent.

`nc.Publish` returns nil on a denied publish, so a missing grant means the
node never pulls, keeps heartbeating, and nothing is logged. The subjects the
worker uses are declared in ONE place, node-agent-go/internal/jobs/
embedpull_subjects.go, and this test parses that file and `perms_for`.

BOTH DIRECTIONS: every subject the worker uses is allowed and not denied, and
every WORK_EMBED grant is used by the worker (no privilege nothing needs).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "noo-cli/src/commands/nats_users.rs"
CONSTS = ROOT / "node-agent-go/internal/jobs/embedpull_subjects.go"

# A model slug, as the gateway builds it: lowercase, [a-z0-9_-].
SAMPLE_CONSUMER = "embed_bge-m3"
# The tokens JetStream appends to an ack subject after the consumer name.
ACK_TAIL = "1.5.7.1700000000.0"


def _node_lists() -> dict[str, list[str]]:
    src = RUST.read_text()
    arm = re.search(r"Role::Node\s*=>\s*format!\((.*?)\n\s*\),", src, re.S)
    assert arm, "the Role::Node arm of perms_for has changed shape"
    out: dict[str, list[str]] = {}
    for section in ("publish", "subscribe"):
        for field in ("allow", "deny"):
            block = re.search(rf"{section}:.*?{field}:\s*\[(.*?)\]", arm.group(1), re.S)
            assert block, f"no {section}/{field} list in the Node arm"
            out[f"{section}.{field}"] = re.findall(r'\\"([^"\\]+)\\"', block.group(1))
    return out


def _consts() -> dict[str, str]:
    found = dict(re.findall(r'^\s*(Embed\w+)\s*=\s*"([^"]*)"', CONSTS.read_text(), re.M))
    return found


def _matches(pattern: str, subject: str) -> bool:
    """NATS matching: `*` is one WHOLE token, `>` is one-or-more tokens."""
    p, s = pattern.split("."), subject.split(".")
    for i, tok in enumerate(p):
        if tok == ">":
            return len(s) > i
        if i >= len(s) or (tok != "*" and tok != s[i]):
            return False
    return len(s) == len(p)


def _worker_subjects() -> dict[str, str]:
    """name -> a concrete subject the worker sends/receives, for a sample consumer."""
    c = _consts()
    out = {}
    for name in ("EmbedConsumerInfoSubjectFmt", "EmbedConsumerNextSubjectFmt"):
        assert name in c, f"{name} missing from {CONSTS.name}"
        out[name] = c[name] % SAMPLE_CONSUMER if "%s" in c[name] else c[name]
    ack = c["EmbedAckSubjectFmt"]
    assert ack.endswith(".>"), "the ack subject shape must end in `.>` (server-appended tokens)"
    out["EmbedAckSubjectFmt"] = ack[:-1].replace("%s", SAMPLE_CONSUMER) + ACK_TAIL
    return out


def _embed_grants() -> list[str]:
    return [g for g in _node_lists()["publish.allow"] if "WORK_EMBED" in g]


def test_the_parse_actually_found_both_sides() -> None:
    c = _consts()
    assert c.get("EmbedStream") == "WORK_EMBED", c
    assert c.get("EmbedConsumerPrefix") == "embed_", c
    assert len(_worker_subjects()) == 3
    for s in _worker_subjects().values():
        assert "%s" not in s and "WORK_EMBED" in s, s
    grants = _embed_grants()
    assert len(grants) == 3, f"expected INFO, MSG.NEXT and ACK grants for WORK_EMBED: {grants}"
    assert _node_lists()["publish.deny"], "parsed an empty deny list"
    # The sample consumer must itself be a pull-consumer name the worker uses.
    assert SAMPLE_CONSUMER.startswith(c["EmbedConsumerPrefix"])


def test_every_subject_the_worker_uses_is_allowed() -> None:
    allow = _node_lists()["publish.allow"]
    for name, subject in _worker_subjects().items():
        assert any(_matches(a, subject) for a in allow), (
            f"the pull worker uses {name} = {subject!r} but the node credential "
            f"does not allow publishing it. nc.Publish would return nil and the "
            f"node would silently never pull."
        )


def test_no_deny_rule_voids_a_pull_subject() -> None:
    deny = _node_lists()["publish.deny"]
    for name, subject in _worker_subjects().items():
        hit = [d for d in deny if _matches(d, subject)]
        assert not hit, f"{name} ({subject!r}) is denied by {hit}; deny wins over allow"
    # `work.` is the stream's subject root; it must not be swallowed by the
    # neighbouring `worker.>` or `tasks.>` denies.
    for subject in ("work.embed.bge-m3",):
        hit = [d for d in deny + _node_lists()["subscribe.deny"] if _matches(d, subject)]
        assert not hit, f"{subject!r} denied by {hit}"


def test_every_work_embed_grant_is_used_by_the_worker() -> None:
    used = list(_worker_subjects().values())
    for g in _embed_grants():
        assert any(_matches(g, u) for u in used), (
            f"the node credential grants {g!r} but the pull worker uses nothing "
            f"it covers; drop the grant or declare the subject in {CONSTS.name}"
        )


def test_a_node_binds_but_never_creates_or_administers() -> None:
    allow = _node_lists()["publish.allow"]
    assert not [a for a in allow if "WORK_EMBED" in a and ("CONSUMER.CREATE" in a or "CONSUMER.DELETE" in a or "STREAM." in a)]
    # `embed_*` inside a token is a LITERAL asterisk to the server, not a
    # wildcard; a grant written that way would match nothing.
    assert not [a for a in allow if re.search(r"[^.]\*|\*[^.]", a)], allow


def test_the_reply_inbox_is_already_granted() -> None:
    """Fetch's reply subject is `<NewInbox()>.<id>` (js.go:1903, 3155), and
    NewInbox honours the connection's custom prefix, so the node's existing
    inbox subscribe grant covers it."""
    sub = _node_lists()["subscribe.allow"]
    assert any(s.startswith("_INBOX_node_") and s.endswith(".>") for s in sub), sub
