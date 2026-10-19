# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Gateway-bound clients REQUIRE a CA; TLS verification is never switched off (510).

`AgentMessenger` used to build its client with `verify=NOO_TLS_CA or False`
(then `or True`): an unset variable meant no verification, then a silent
system-store fallback. The operator rule is TLS everywhere, fail loud, no
insecure escape hatch. So:

  * no CA anywhere -> `TlsCaMissing`, naming NOO_TLS_CA, at client build;
  * a CA path is honoured and handed to httpx as `verify`;
  * `cli_http_verify()` over https does the same instead of returning False;
  * the verification-off idioms appear nowhere in the tree except an
    allow-list, each entry with its reason (a stale entry fails).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from noomesh.tls_ca import TlsCaMissing, require_ca, resolve_ca

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def no_ca(monkeypatch, tmp_path):
    monkeypatch.delenv("NOO_TLS_CA", raising=False)
    monkeypatch.setenv("NOO_PKI_DIR", str(tmp_path / "empty-pki"))
    monkeypatch.setattr("noomesh.tls_ca.CONTAINER_CA_PATHS", (str(tmp_path / "nope.crt"),))


def test_no_ca_raises_and_names_the_setting(no_ca):
    with pytest.raises(TlsCaMissing, match="NOO_TLS_CA"):
        require_ca()


def test_a_ca_path_is_honoured(monkeypatch, tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    monkeypatch.setenv("NOO_TLS_CA", str(ca))
    assert require_ca() == str(ca)


def test_a_set_but_missing_ca_is_an_error_not_a_fall_through(monkeypatch, tmp_path):
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text("x")
    monkeypatch.setenv("NOO_PKI_DIR", str(pki))
    monkeypatch.setenv("NOO_TLS_CA", str(tmp_path / "typo.crt"))
    with pytest.raises(TlsCaMissing, match="NOO_TLS_CA"):
        resolve_ca()


def test_the_install_pki_dir_is_the_fallback(no_ca, monkeypatch, tmp_path):
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text("x")
    monkeypatch.setenv("NOO_PKI_DIR", str(pki))
    assert require_ca() == str(pki / "ca.crt")


def test_agent_messenger_refuses_to_build_a_client_without_a_ca(no_ca):
    from noomesh.agents.messaging import AgentMessenger

    m = AgentMessenger.__new__(AgentMessenger)
    with pytest.raises(TlsCaMissing, match="NOO_TLS_CA"):
        m._client()


def test_agent_messenger_client_verifies_against_the_given_ca(monkeypatch, tmp_path):
    import httpx

    from noomesh.agents import messaging

    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    monkeypatch.setenv("NOO_TLS_CA", str(ca))
    monkeypatch.setattr(messaging.AgentMessenger, "_headers", staticmethod(lambda: {}))
    seen = {}

    class Spy(httpx.Client):
        def __init__(self, *a, **kw):
            seen.update(kw)
            # a real CA bundle is not needed to record what was asked for
            super().__init__(*a, **{**kw, "verify": True})

    monkeypatch.setattr(httpx, "Client", Spy)
    m = messaging.AgentMessenger.__new__(messaging.AgentMessenger)
    m._client().close()
    assert seen["verify"] == str(ca)


def test_cli_http_verify_is_never_false_without_a_ca(no_ca, monkeypatch):
    from noomesh import cli_utils

    monkeypatch.setattr(cli_utils, "get_gateway_url", lambda: "https://localhost:8080")
    assert cli_utils.cli_http_verify() is True


def test_cli_http_verify_returns_the_ca_path(monkeypatch, tmp_path):
    from noomesh import cli_utils

    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    monkeypatch.setenv("NOO_TLS_CA", str(ca))
    monkeypatch.setattr(cli_utils, "get_gateway_url", lambda: "https://localhost:8080")
    assert cli_utils.cli_http_verify() == str(ca)


# ---- the grep guard -------------------------------------------------------

FORBIDDEN = (
    re.compile(r"verify\s*=\s*False"),
    re.compile(r"InsecureSkipVerify\s*:\s*true"),
    re.compile(r"\.danger_accept_invalid_(certs|hostnames)\(\s*true"),
    re.compile(r"ssl\.CERT_NONE"),
    re.compile(r"check_hostname\s*(=\s*False|:\s*false)"),
    re.compile(r"_create_unverified_context"),
    re.compile(r"(?<![\w-])curl\b[^|;&\n]*\s-[a-zA-Z]*k[a-zA-Z]*\s"),
    re.compile(r"--insecure\b"),
)

SCAN = ("src", "gateway-rust/src", "noo-cli/src", "node-agent-go", "packages", "scripts", "docker", "plugins", "eval")
SUFFIXES = {".py", ".rs", ".go", ".sh", ".yml", ".yaml", ".toml", ""}
SKIP_PARTS = {"target", "node_modules", ".git", "__pycache__", "tests"}

# path -> why a hit there is legitimate. A stale entry fails, so the list cannot rot.
ALLOWED = {
    "scripts/bootstrap-enroll.sh": "the ONE unverified request of the shell enrollment lane: it fetches the "
    "public CA certificate (/bootstrap/ca.crt), checks its sha256 against the paste's pin, and sends the token and "
    "fetches the root prep script only under --cacert of that CA (tests/test_prep_tofu_is_pinned.py enforces both)",
    "docker/Dockerfile.sandbox": "HEALTHCHECK probe of localhost inside the per-call sandbox namespace; "
    "operator-deferred 2026-09-29 (tests/test_healthchecks_verify_tls.py)",
    "scripts/noomesh-sandbox.sh": "sandbox smoke helper probing https://localhost:8080/health in the "
    "throwaway sandbox before its CA is mounted; same deferral as Dockerfile.sandbox",
    "packages/noo-gateway-client/src/noo_gateway/settings.py": "the REFUSAL: raises on verify=False",
    # Source that only DISCUSSES the idiom in comments:
    "src/noomesh/security_cli.py": "comment: never verify=False",
    "src/noomesh/cluster/model_catalog.py": "comment: NEVER verify=False",
    "src/noomesh/gateway/deps.py": "docstring recounting the removed check_hostname = False",
    "noo-cli/src/onboard/sh.rs": "comment quoting the old Python verify=False",
    "noo-cli/src/commands/security_local.rs": "comments quoting the old Python verify=False",
}


def _files():
    out = subprocess.run(["git", "ls-files", *SCAN], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for rel in out.splitlines():
        p = ROOT / rel
        if SKIP_PARTS & set(p.relative_to(ROOT).parts) or not (p.suffix in SUFFIXES or p.name.startswith("Dockerfile")) or not p.is_file():
            continue
        yield rel, p


def _hits(text: str) -> list[str]:
    return [f.pattern for f in FORBIDDEN if f.search(text)]


def test_no_verification_off_idiom_outside_the_allow_list():
    scanned, bad, used = 0, [], set()
    for rel, p in _files():
        try:
            text = p.read_text()
        except UnicodeDecodeError:
            continue
        scanned += 1
        h = _hits(text)
        if not h:
            continue
        if rel in ALLOWED:
            used.add(rel)
        else:
            bad.append(f"{rel}: {h}")
    assert scanned > 200, f"only {scanned} files scanned -- vacuous"
    assert not bad, "TLS verification switched off (no insecure escape hatch):\n  " + "\n  ".join(bad)
    stale = sorted(set(ALLOWED) - used)
    assert not stale, f"allow-list entries no longer match anything -- remove them: {stale}"


def test_the_guard_catches_a_planted_violation():
    for line in ('httpx.Client(verify=False)', "ctx.verify_mode = ssl.CERT_NONE", "InsecureSkipVerify: true",
                 ".danger_accept_invalid_certs(true)", "curl -k https://x", "curl -fsSk https://x ", "--insecure"):
        assert _hits(line), line
    assert not _hits("httpx.Client(verify=require_ca())")
