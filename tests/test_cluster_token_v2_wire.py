# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The request-bound cluster token (v2) is one wire format in three signers.

`gateway-rust/src/cluster_token_v2.rs` verifies it, `node-agent-go/internal/
auth/clustertoken_v2.go` signs and verifies it, and `scripts/noo-fetch.sh`
signs it in shell. They cannot see each other, so this pins them to the same
bytes: one shared test vector in all three files, and the shell signer run for
real and checked against an independent Python implementation of the spec.

The properties (a replay is refused, a body/path/method change is refused, v1
is always refused) are asserted where the verifier
lives: `cluster_token_v2.rs` tests and `clustertoken_v2_test.go`.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "gateway-rust/src/cluster_token_v2.rs"
GO = ROOT / "node-agent-go/internal/auth/clustertoken_v2_test.go"
FETCH = ROOT / "scripts/noo-fetch.sh"

VECTOR_SIG = "3aee59b3fc968f448b71de5aeb463044b25a26a3ef8ccdff6fc3d53cbbe59540"


def v2_message(method, uri, body, actor, ts, nonce) -> bytes:
    return "\n".join(["v2", method.upper(), uri, hashlib.sha256(body).hexdigest(), actor, str(ts), nonce]).encode()


def v2_sig(secret, *args) -> str:
    return hmac.new(secret.encode(), v2_message(*args), hashlib.sha256).hexdigest()


def test_the_reference_implementation_reproduces_the_shared_vector():
    sig = v2_sig("s3cret", "POST", "/bootstrap/bundle/host1/applied", b'{"a":1}', "host1", 1700000000,
                 "00112233445566778899aabbccddeeff")
    assert sig == VECTOR_SIG


def test_rust_and_go_pin_the_same_vector():
    for p in (RUST, GO):
        assert VECTOR_SIG in p.read_text(), f"{p.name} does not carry the shared vector"


def _node_bearer_fn() -> str:
    text = FETCH.read_text()
    m = re.search(r"^node_bearer\(\) \{\n.*?^\}\n", text, re.S | re.M)
    assert m, "node_bearer() not found in noo-fetch.sh"
    return m.group(0)


def _run_bearer(tmp_path: Path, form: str | None, *args: str) -> str:
    env = tmp_path / "agent.env"
    env.write_text("NOO_CLUSTER_SECRET=s3cret\n")
    fn = _node_bearer_fn().replace("/etc/noo-node-agent.env", str(env))
    script = fn + "\nnode_bearer " + " ".join(f"'{a}'" for a in args) + "\n"
    e = {"NODE": "host2", "PATH": "/usr/bin:/bin"}
    if form:
        e["NOO_BEARER_FORM"] = form
    out = subprocess.run(["sh", "-c", script], env=e, capture_output=True, text=True, check=True)
    return out.stdout


def test_the_shell_signer_emits_a_v2_token_the_spec_verifies(tmp_path):
    body = '{"sha":"abc","rc":0,"msg":"ok"}'
    tok = _run_bearer(tmp_path, None, "POST", "/bootstrap/bundle/host2/applied", body)
    kind, actor, ts, nonce, sig = tok.split(":")
    assert (kind, actor) == ("v2", "host2")
    assert len(nonce) == 32 and int(nonce, 16) >= 0
    want = v2_sig("s3cret", "POST", "/bootstrap/bundle/host2/applied", body.encode(), "host2", int(ts), nonce)
    assert sig == want, "the shell signer does not sign what the verifiers check"
    # ...and it is bound: the same token does not verify for another body or path.
    assert sig != v2_sig("s3cret", "POST", "/bootstrap/bundle/host2/applied", b"{}", "host2", int(ts), nonce)
    assert sig != v2_sig("s3cret", "POST", "/bootstrap/bundle/host3/applied", body.encode(), "host2", int(ts), nonce)


def test_every_shell_token_has_a_fresh_nonce(tmp_path):
    a = _run_bearer(tmp_path, None, "GET", "/x", "")
    b = _run_bearer(tmp_path, None, "GET", "/x", "")
    assert a.split(":")[3] != b.split(":")[3], "a reused nonce is a replay the gateway would refuse"


def test_the_shell_has_no_v1_signer_and_ignores_the_old_pin(tmp_path):
    src = FETCH.read_text()
    fn = _node_bearer_fn()
    assert "node_sign_form" not in src and "NOO_BEARER_FORM" not in src, "the v1 signing branch is deleted"
    assert "-hex" in fn and "v2\\n" in fn, "node_bearer must still sign v2 (the guard must scan the signer)"
    # A node whose env still carries the old pin (or the old gate line) signs v2.
    env = tmp_path / "agent.env"
    env.write_text("NOO_CLUSTER_SECRET=s3cret\nNOO_CLUSTER_TOKEN_SIGN=v1\nNOO_CLUSTER_TOKEN_V1=0\n")
    script = fn.replace("/etc/noo-node-agent.env", str(env)) + "\nnode_bearer 'POST' '/x' '{}'\n"
    out = subprocess.run(["sh", "-c", script], env={"NODE": "host2", "PATH": "/usr/bin:/bin"},
                         capture_output=True, text=True, check=True).stdout
    assert out.startswith("v2:host2:"), out
    body = re.search(r"^report_post\(\) \{\n(.*?)^\}", src, re.S | re.M).group(1)
    # No v1 retry after a 401: that retry was the controller's
    # cluster_hmac_v1 count of one per node per applied bundle.
    assert "continue" not in body, "report_post must not re-send a refused v2 report"
    assert "node_bearer POST" in body


def test_the_shell_report_mints_per_attempt_and_sends_the_body_hash():
    src = FETCH.read_text()
    assert "authorization: Bearer @NODE_BEARER@" in src, "the report must not pre-mint a bearer that its retries would replay"
    assert "x-noo-content-sha256" in src, "the gateway's rate limiter checks the signature against this header"


def test_grafana_session_ttl_default_is_one_number_everywhere():
    """url_login puts the token in the URL; its lifetime is the bound. The
    default must agree across the gateway constant, compose and .env.example."""
    auth = (ROOT / "gateway-rust/src/auth.rs").read_text()
    n = int(re.search(r"GRAFANA_SESSION_DEFAULT_MINUTES: u64 = (\d+);", auth).group(1))
    assert n <= 5, "the Grafana token rides the URL; do not lengthen it"
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    assert f"NOO_GRAFANA_SESSION_TTL=${{NOO_GRAFANA_SESSION_TTL:-{n}}}" in compose
    assert f"NOO_GRAFANA_SESSION_TTL={n}\n" in (ROOT / ".env.example").read_text()
    ini = (ROOT / "configs/grafana/grafana.ini").read_text()
    assert "url_login = true" in ini and "url_login STAYS" in ini, "the reason url_login stays must sit beside it"


def test_security_config_debug_is_manual():
    src = (ROOT / "gateway-rust/src/config.rs").read_text()
    decl = src.split("pub struct SecurityConfig")[0].rsplit("#[derive", 1)[1].split("]", 1)[0]
    assert "Debug" not in decl, "SecurityConfig derives Debug again: jwt_secret and cluster_secret would print"
    assert "impl std::fmt::Debug for SecurityConfig" in src
