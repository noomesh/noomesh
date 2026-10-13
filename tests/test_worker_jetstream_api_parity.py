# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The worker's JetStream API calls must agree with its bus credential.

2026-10-06, live on host8: noo-worker, noo-trellion and noo-trellion-intel each
logged, at every start, a permission violation for
`$js.api.stream.create.tasks` / `.events` followed by `stream_creation_failed
error='nats: timeout'`. The worker's NATS user is (correctly) denied stream
creation; the Rust gateway owns it (`ensure_job_plane_streams`). The Python
client was a leftover creator. Nothing was lost -- the streams existed -- but
every start burned a timeout per stream and logged an error that answered the
wrong question, and a genuinely missing stream would have been reported as a
"creation failure" rather than as a missing stream.

Static, source-level, like test_nats_node_subject_parity.py: NATS reports a
denied publish asynchronously, so a runtime test cannot see it.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MESSAGING = ROOT / "src" / "noomesh" / "cluster" / "messaging.py"
USERS = ROOT / "noo-cli" / "src" / "commands" / "nats_users.rs"


def _worker_perm_block() -> str:
    src = USERS.read_text()
    start = src.index("Role::Worker => format!(")
    end = src.index("Role::Node => format!(", start)
    return src[start:end]


def _worker_publish_lists() -> tuple[list[str], list[str]]:
    block = _worker_perm_block()
    pub = block.split("subscribe:")[0]
    allow = re.search(r'allow: \[(.*?)\]', pub, re.S).group(1)
    deny = re.search(r'deny: \[(.*?)\]', pub, re.S).group(1)
    q = lambda t: re.findall(r'\\"([^"\\]+)\\"', t)
    return q(allow), q(deny)


def test_worker_never_calls_stream_mutations():
    """Stream create/update/delete/purge are denied to the worker; the gateway
    owns them. Any such call in the client is a guaranteed permission violation."""
    code = "\n".join(
        l for l in MESSAGING.read_text().splitlines() if not l.lstrip().startswith("#")
    )
    bad = re.findall(r"\.(add_stream|update_stream|delete_stream|purge_stream|"
                     r"streams_info_create|create_stream)\(", code)
    assert not bad, (
        f"messaging.py calls {sorted(set(bad))}, but the worker credential denies "
        "$JS.API.STREAM.CREATE/UPDATE/DELETE/PURGE. The gateway owns the job-plane "
        "streams; verify with stream_info instead."
    )


def test_stream_verification_is_granted():
    """What the client does instead -- stream_info -- must be authorised."""
    assert "stream_info(" in MESSAGING.read_text()
    allow, deny = _worker_publish_lists()
    assert "$JS.API.STREAM.INFO.*" in allow
    assert not any(d.startswith("$JS.API.STREAM.INFO") for d in deny)


def test_streams_the_client_requires_are_gateway_created():
    """Every stream the client verifies must be one the gateway creates, else
    the worker would loudly demand something nobody provides."""
    m = re.search(r"REQUIRED_STREAMS\s*=\s*\(([^)]*)\)", MESSAGING.read_text())
    assert m, "REQUIRED_STREAMS missing"
    required = set(re.findall(r'"([A-Z_]+)"', m.group(1)))
    gw = (ROOT / "gateway-rust" / "src" / "scheduler_engine.rs").read_text()
    created = set(re.findall(r'name: "([A-Z_]+)"\.to_string\(\)', gw))
    assert required and required <= created, (required, created)


async def test_verify_streams_binds_not_creates_and_fails_loudly(monkeypatch):
    from nats.js.errors import NotFoundError

    from noomesh.cluster import messaging as mod

    class JS:
        def __init__(self):
            self.info, self.created = [], []

        async def stream_info(self, name):
            self.info.append(name)
            if name == "TASKS":
                raise NotFoundError()

        async def add_stream(self, **kw):  # pragma: no cover
            self.created.append(kw)

    logged = []
    monkeypatch.setattr(mod.logger, "error", lambda ev, **kw: logged.append((ev, kw)))
    m = mod.ClusterMessaging("nats://test:4222")
    m.js = JS()
    await m._verify_streams()

    assert m.js.created == [], "worker must not create streams"
    assert sorted(m.js.info) == ["EVENTS", "TASKS"]
    assert [(e, k["name"]) for e, k in logged] == [("stream_missing", "TASKS")]
