# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo-fetch.sh`'s apply report never sends the fleet token without the node's leaf.

an earlier change counted `node_token_no_cert` = 1 from worker-1 during the
stack-v0.2.82 roll: the apply report (`POST /bootstrap/bundle/<node>/applied`)
signed with NOO_CLUSTER_SECRET and presented no client certificate. The
report's functions are lifted out of the real script and run under `sh` with
`curl` and `birth_proof` stubbed, so each case asserts on the argv curl WOULD
have been called with:

- secret + leaf on disk  -> `--cert` / `--key` AND the bearer (and the proof);
- secret, leaf missing   -> the birth proof alone, no bearer;
- applier-only first pass (no agent env at all) -> the birth proof alone;
- the leaf is refused at the handshake -> one retry on the birth proof alone,
  still no bearer, and the script survives to report the apply's own rc.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/noo-fetch.sh"
FUNCS = ("node_bearer", "node_tls", "report", "report_post")
AGENT_ENV = "/etc/noo-node-agent.env"
SHA = "a" * 64

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="node_bearer signs with openssl")


def _functions() -> str:
    text = SCRIPT.read_text()
    out = []
    for name in FUNCS:
        m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.S | re.M)
        assert m, f"noo-fetch.sh has no {name}() — this test reads the real functions, it must find them"
        out.append(m.group(0))
    body = "\n".join(out)
    # node_bearer and node_tls both read the agent's env file — the path the
    # agent's provisioning writes. Pinned here, then pointed at the case's.
    assert body.count(f"_env={AGENT_ENV}") == 2, "node_bearer and node_tls read the agent env file"
    return body


def _run(
    tmp_path: Path,
    env_lines: list[str] | None,
    *,
    cert_curl_rc: int = 0,
    fail_first: int = 0,
    http_code: str = "200",
    stderr_out: list[str] | None = None,
) -> list[list[str]]:
    agent_env = tmp_path / "noo-node-agent.env"
    if env_lines is not None:
        agent_env.write_text("\n".join(env_lines) + "\n")
    (tmp_path / "apply.log").write_text("applied ok\n")
    calls = tmp_path / "curl.calls"
    harness = f"""
set -eu
TMP={tmp_path}; NODE=worker-1; SUM={SHA}; URL=https://ctl.example:8080
TLS="--cacert {tmp_path}/ca.crt"
birth_proof() {{ printf '%s' '1700000000.c2lnbmF0dXJl'; }}
sleep() {{ echo "$1" >> {tmp_path}/sleeps; }}
curl() {{
    _stub_rc=0
    _n=$(cat {tmp_path}/n 2>/dev/null || echo 0); _n=$((_n + 1)); echo $_n > {tmp_path}/n
    for _a in "$@"; do
        printf '%s\\n' "$_a" >> {calls}
        if [ "$_a" = --cert ]; then _stub_rc={cert_curl_rc}; fi
    done
    printf '%s\\n' '<<end>>' >> {calls}
    if [ "$_n" -le {fail_first} ]; then echo "curl: (7) Failed to connect: Network is unreachable" >&2; return 7; fi
    if [ "$_stub_rc" -ne 0 ]; then return $_stub_rc; fi
    printf '%s' {http_code}
    return 0
}}
{_functions().replace(f"_env={AGENT_ENV}", f"_env={agent_env}")}
report 0
echo reached-the-end
"""
    proc = subprocess.run(["sh", "-c", harness], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "reached-the-end" in proc.stdout, proc.stderr
    if stderr_out is not None:
        stderr_out.append(proc.stderr)
    if not calls.exists():
        return []
    out, cur = [], []
    for line in calls.read_text().splitlines():
        if line == "<<end>>":
            out.append(cur)
            cur = []
        else:
            cur.append(line)
    return out


def _leaf(tmp_path: Path) -> tuple[Path, Path]:
    crt, key = tmp_path / "node.crt", tmp_path / "node.key"
    crt.write_text("cert\n")
    key.write_text("key\n")
    return crt, key


def _has_bearer(argv: list[str]) -> bool:
    return any(a.lower().startswith("authorization: bearer ") for a in argv)


def test_the_token_goes_with_the_nodes_leaf(tmp_path: Path) -> None:
    crt, key = _leaf(tmp_path)
    calls = _run(tmp_path, [
        "NODE_ID=worker-1",
        "NOO_CLUSTER_SECRET='fleet-secret'",
        f'NOO_TLS_CERT="{crt}"',
        f"NOO_TLS_KEY={key}",
    ])
    assert len(calls) == 1, calls
    argv = calls[0]
    assert argv[argv.index("--cert") + 1] == str(crt), argv
    assert argv[argv.index("--key") + 1] == str(key), argv
    assert _has_bearer(argv), argv
    bearer = next(a for a in argv if a.lower().startswith("authorization: bearer "))
    assert re.fullmatch(r"authorization: Bearer v2:worker-1:\d+:[0-9a-f]{32}:[0-9a-f]{64}", bearer), bearer
    # ...and it is bound to THIS report: the method, the path and the exact
    # body curl sends (-d), under the fleet secret.
    import hashlib, hmac
    _, node, ts, nonce, sig = bearer.split("Bearer ", 1)[1].split(":")
    body = argv[argv.index("-d") + 1]
    msg = "\n".join(["v2", "POST", "/bootstrap/bundle/worker-1/applied", hashlib.sha256(body.encode()).hexdigest(), "worker-1", ts, nonce]).encode()
    assert sig == hmac.new(b"fleet-secret", msg, hashlib.sha256).hexdigest(), bearer
    assert f"x-noo-content-sha256: {hashlib.sha256(body.encode()).hexdigest()}" in argv, argv
    assert "x-noo-birth-proof: 1700000000.c2lnbmF0dXJl" in argv, argv
    assert argv[-1] == "https://ctl.example:8080/bootstrap/bundle/worker-1/applied", argv


def test_no_leaf_means_no_token(tmp_path: Path) -> None:
    calls = _run(tmp_path, [
        "NOO_CLUSTER_SECRET=fleet-secret",
        f"NOO_TLS_CERT={tmp_path}/missing.crt",
        f"NOO_TLS_KEY={tmp_path}/missing.key",
    ])
    assert len(calls) == 1, calls
    assert "--cert" not in calls[0] and not _has_bearer(calls[0]), calls[0]
    assert "x-noo-birth-proof: 1700000000.c2lnbmF0dXJl" in calls[0], calls[0]


def test_applier_only_first_pass_reports_on_the_birth_proof(tmp_path: Path) -> None:
    calls = _run(tmp_path, None)
    assert len(calls) == 1, calls
    assert "--cert" not in calls[0] and not _has_bearer(calls[0]), calls[0]
    assert "x-noo-birth-proof: 1700000000.c2lnbmF0dXJl" in calls[0], calls[0]


def test_a_refused_leaf_retries_on_the_proof_alone_never_the_bare_token(tmp_path: Path) -> None:
    crt, key = _leaf(tmp_path)
    calls = _run(tmp_path, [
        "NOO_CLUSTER_SECRET=fleet-secret",
        f"NOO_TLS_CERT={crt}",
        f"NOO_TLS_KEY={key}",
    ], cert_curl_rc=35)
    assert len(calls) == 2, calls
    assert "--cert" in calls[0] and _has_bearer(calls[0]), calls[0]
    assert "--cert" not in calls[1] and not _has_bearer(calls[1]), calls[1]
    assert "x-noo-birth-proof: 1700000000.c2lnbmF0dXJl" in calls[1], calls[1]


def _agent(tmp_path: Path) -> list[str]:
    crt, key = _leaf(tmp_path)
    return ["NOO_CLUSTER_SECRET=fleet-secret", f"NOO_TLS_CERT={crt}", f"NOO_TLS_KEY={key}"]


def test_a_report_sent_while_the_link_is_down_is_retried_until_it_lands(tmp_path: Path) -> None:
    # tailscaled restarts inside noo-apply: the first rounds (cert + proof each)
    # find no route. Four failed curls = two rounds, then the third round lands.
    err: list[str] = []
    calls = _run(tmp_path, _agent(tmp_path), fail_first=4, stderr_out=err)
    assert len(calls) == 5, calls
    assert "--cert" in calls[4], calls[4]
    assert (tmp_path / "sleeps").read_text().split() == ["10", "10"]
    assert err[0].count("apply report delivered (HTTP 200)") == 1, err[0]
    assert "controller unreachable" not in err[0], err[0]


def test_a_controller_that_never_answers_is_given_up_on_after_the_window(tmp_path: Path) -> None:
    err: list[str] = []
    calls = _run(tmp_path, None, fail_first=10_000, stderr_out=err)
    assert len(calls) == 10, calls  # t=0 .. t=90 in 10 s steps, one proof-only attempt each
    assert (tmp_path / "sleeps").read_text().split() == ["10"] * 9
    assert "controller unreachable for 90 s after the apply — tailscaled restart?" in err[0], err[0]
    assert "Network is unreachable" in err[0], err[0]


def test_an_http_refusal_is_a_verdict_not_a_reason_to_wait(tmp_path: Path) -> None:
    err: list[str] = []
    calls = _run(tmp_path, None, http_code="403", stderr_out=err)
    assert len(calls) == 1, calls
    assert not (tmp_path / "sleeps").exists()
    assert "apply report refused (HTTP 403)" in err[0], err[0]
