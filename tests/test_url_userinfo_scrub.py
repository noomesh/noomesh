# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Service URLs are logged without their userinfo, in both languages.

`NATS_URL` and `REDIS_URL` accept `scheme://user:password@host:port`. Found
2026-09-29: the gateway logged both raw at every connect
(`gateway-rust/src/cache.rs`, `state.rs`, `bus.rs`) and the Python cluster
client logged the NATS URL raw in six events (`cluster/messaging.py`:
connected, timeout, error, disconnected, closed, reconnected — the last
four fire on every flap). An operator who put the password in the URL had
it in the journal many times over; `docker logs` is pasted freely during
an incident, which is exactly when that happens.

One scrubber per language (`redact::scrub_url_userinfo` in Rust,
`noomesh.redact.scrub_url_userinfo` in Python), structural rather than a
regex over the whole line. This file exercises the Python one over the
same vectors the Rust unit tests use, and pins that every raw site in both
languages goes through its scrubber (a source grep: the sites are named
above, and a new `url = %<var>` line must not quietly reintroduce one).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from noomesh.redact import scrub_url_userinfo

ROOT = Path(__file__).resolve().parents[1]

VECTORS = [
    ("rediss://:hunter2@redis:6379/0", "rediss://redis:6379/0"),
    ("tls://noo:s3cret@nats:4222", "tls://nats:4222"),
    ("rediss://u:p@ss@redis:6379", "rediss://redis:6379"),  # password containing '@': cut at the LAST one
    ("https://h:1/x@y?u=a@b", "https://h:1/x@y?u=a@b"),  # '@' past the authority is data
    ("rediss://redis:6379", "rediss://redis:6379"),
    ("tls://nats:4222", "tls://nats:4222"),
    ("redis:6379", "redis:6379"),  # no scheme: readable as-is
    ("", ""),
]


@pytest.mark.parametrize(("raw", "expect"), VECTORS)
def test_the_python_scrubber(raw: str, expect: str) -> None:
    assert scrub_url_userinfo(raw) == expect


def test_no_raw_nats_url_reaches_the_python_log() -> None:
    src = (ROOT / "src/noomesh/cluster/messaging.py").read_text()
    # A log kwarg (`url=self.nats_url` after `(` or `,`), not the field's own assignment.
    raw = [ln.strip() for ln in src.splitlines() if re.search(r"[(,]\s*url\s*=\s*self\.nats_url\b", ln)]
    assert not raw, "messaging.py logs the NATS URL raw again:\n" + "\n".join(raw)
    assert src.count("scrub_url_userinfo(self.nats_url)") >= 6, "the six log events must all go through the scrubber"


def test_every_rust_connect_log_goes_through_the_scrubber() -> None:
    """`tracing::…!(url = %X` where X is a connection URL must wrap it."""
    raw: list[str] = []
    scrubbed = 0
    for rel in ("gateway-rust/src/cache.rs", "gateway-rust/src/state.rs", "gateway-rust/src/bus.rs"):
        for n, line in enumerate((ROOT / rel).read_text().splitlines(), 1):
            m = re.search(r"tracing::\w+!\(.*\burl\s*=\s*%(\S+)", line)
            if not m:
                continue
            if m.group(1).startswith("crate::redact::scrub_url_userinfo("):
                scrubbed += 1
            else:
                raw.append(f"{rel}:{n}: {line.strip()}")
    assert not raw, "a connection URL is logged raw (userinfo included):\n" + "\n".join(raw)
    assert scrubbed >= 4, f"expected the four known sites to be scrubbed, found {scrubbed}"
    assert "pub fn scrub_url_userinfo" in (ROOT / "gateway-rust/src/redact.rs").read_text()


def test_every_go_url_log_goes_through_the_scrubber() -> None:
    """The node agent's twin: every `"url", X` slog pair in
    node-agent-go wraps X in `ScrubURLUserinfo(`, and the heartbeat/`/health`
    bus status reports the scrubbed URL. The Go unit test
    (`logship.TestScrubURLUserinfo`) holds the same VECTORS."""
    raw: list[str] = []
    scrubbed = 0
    for path in sorted((ROOT / "node-agent-go").rglob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        rel = path.relative_to(ROOT)
        for n, line in enumerate(path.read_text().splitlines(), 1):
            for m in re.finditer(r'"url",\s*([^,)\s][^,]*)', line):
                arg = m.group(1).strip()
                if re.match(r"(logship\.)?ScrubURLUserinfo\(", arg):
                    scrubbed += 1
                else:
                    raw.append(f"{rel}:{n}: {line.strip()}")
    assert not raw, "a connection URL is logged raw by the node agent (userinfo included):\n" + "\n".join(raw)
    assert scrubbed >= 12, f"expected the twelve known Go sites to be scrubbed, found {scrubbed}"
    nats = (ROOT / "node-agent-go/internal/messaging/nats.go").read_text()
    assert "URL:      logship.ScrubURLUserinfo(c.url)," in nats, "the bus status on /health and the heartbeat must carry the scrubbed URL"
    assert 'deliver them)", c.url' not in nats, "the TLS refusal's error text must not echo the raw NATS_URL"
    assert "func ScrubURLUserinfo(" in (ROOT / "node-agent-go/internal/logship/urlscrub.go").read_text()
    go_test = (ROOT / "node-agent-go/internal/logship/urlscrub_test.go").read_text()
    missing = [raw_url for raw_url, _ in VECTORS if f'"{raw_url}"' not in go_test]
    assert not missing, f"the Go vectors drifted from VECTORS: {missing}"
