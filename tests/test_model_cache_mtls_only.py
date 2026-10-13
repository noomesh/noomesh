# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The model-weight store answers mTLS on 8443 and nothing else (phase 2 — 2026-09-29).

Phase 1 kept a plaintext listener on 8083 for one release so an agent
older than the TLS-capable client could keep preseeding; phase 2 deleted
it. What this guard holds, so it cannot come back one edit at a time:

* compose publishes EXACTLY one model-cache port, and it is 8443, on the
  bind address;
* ``docker/model-cache.nginx.conf`` has no ``listen 8083`` (no plain
  ``listen`` at all except the loopback healthz), and its 8443 server keeps
  ``ssl_verify_client on`` plus the ``O=Mesh Cluster Node`` org filter;
* every ``NOO_MODEL_CACHE_URL`` value the tree renders or defaults —
  provision's template variable, compose, scripts, the agent's own
  fallback — is ``https://…:8443``; no ``http://…:8083`` literal survives
  outside prose, tests and the closed-followup archive.

``tests/test_model_cache_serves_no_credentials.py`` owns what the tree
serves; this file owns which listener serves it.
"""

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONF = REPO_ROOT / "docker" / "model-cache.nginx.conf"
COMPOSE = REPO_ROOT / "docker-compose.cluster.yml"

TLS_PORT = "8443"
RETIRED_PLAIN_PORT = "8083"


def _strip_comments(text: str) -> str:
    return "\n".join(re.sub(r"#.*$", "", line) for line in text.splitlines())


@pytest.fixture(scope="module")
def listeners():
    return _strip_comments(CONF.read_text())


def _servers(text):
    return re.findall(r"^server\s*\{(.*?)^\}", text, re.S | re.M)


def _listen_lines(server_body):
    """[(address, flags)] for each `listen` directive."""
    out = []
    for m in re.finditer(r"^\s*listen\s+([^;]+);", server_body, re.M):
        parts = m.group(1).split()
        out.append((parts[0], parts[1:]))
    return out


def _model_cache_service():
    return yaml.safe_load(COMPOSE.read_text())["services"]["model-cache"]


# ── compose: one port, 8443, confined ────────────────────────────────────


def test_compose_publishes_exactly_the_tls_port():
    ports = [str(p) for p in _model_cache_service()["ports"]]
    assert len(ports) == 1, (
        f"model-cache publishes {ports}. Phase 2 of an earlier change left exactly "
        f"one port (:{TLS_PORT}); a second entry is the plaintext listener coming back."
    )
    spec = ports[0]
    assert spec.rsplit(":", 1)[1] == TLS_PORT, spec
    assert spec.startswith("${NOO_BIND_ADDR"), f"{spec!r} is not confined to the bind address"
    assert "NOO_MODEL_CACHE_PORT" not in spec, "the retired NOO_MODEL_CACHE_PORT knob is back"


def test_compose_carries_no_retired_plaintext_knob():
    # Comments may still explain the retirement; code may not consume it.
    code = _strip_comments(COMPOSE.read_text())
    assert "NOO_MODEL_CACHE_PORT" not in code, "NOO_MODEL_CACHE_PORT is consumed by compose again"
    assert not re.search(rf":{RETIRED_PLAIN_PORT}\b", code), f"a :{RETIRED_PLAIN_PORT} appears in compose code"


# ── nginx: no plain listener, the mTLS listener intact ───────────────────


def test_nginx_has_no_plaintext_listener(listeners):
    plain = []
    for body in _servers(listeners):
        for addr, flags in _listen_lines(body):
            if "ssl" in flags:
                continue
            if addr.startswith("127.0.0.1:"):
                continue  # the loopback healthz listener, never published
            plain.append(addr)
    assert not plain, (
        f"plaintext data-plane listener(s) {plain} in docker/model-cache.nginx.conf — "
        "the store serves gated weights; it answers mTLS on 8443 only"
    )
    assert f"listen {RETIRED_PLAIN_PORT}" not in listeners


def test_the_tls_listener_verifies_the_client_and_filters_the_org(listeners):
    tls = [b for b in _servers(listeners) if any("ssl" in f for _, f in _listen_lines(b))]
    assert len(tls) == 1, f"expected exactly one `listen … ssl` server, found {len(tls)}"
    body = tls[0]
    assert any(addr == TLS_PORT for addr, _ in _listen_lines(body)), _listen_lines(body)
    assert re.search(r"^\s*ssl_verify_client\s+on;", body, re.M), "ssl_verify_client is not `on`"
    assert re.search(r"if\s*\(\s*\$mc_peer_ok\s*=\s*0\s*\)\s*\{\s*return\s+403;", body), "the org filter is gone"
    m = re.search(r"map\s+\$ssl_client_s_dn\s+\$mc_peer_ok\s*\{(.*?)\n\}", listeners, re.S)
    assert m, "the $mc_peer_ok map is gone"
    assert re.search(r'O=Mesh Cluster Node\(,\|\$\)"\s+1;', m.group(1)), "O=Mesh Cluster Node is not admitted"
    assert re.search(r"^\s*default\s+0;", m.group(1), re.M), "the map's default must be 0 (deny)"


# ── every NOO_MODEL_CACHE_URL value in the tree is https:8443 ────────────

# Where a cache URL is rendered, defaulted or read. Prose (docs/, internal/),
# tests and the UI are not renderers; a Go test file holds the refused
# values on purpose.
CODE_ROOTS = ("noo-cli/src", "node-agent-go", "gateway-rust/src", "scripts", "docker", "docker-compose.cluster.yml", ".env.example")

PLAIN_URL = re.compile(rf"https?://[^\s\"'`)]+:{RETIRED_PLAIN_PORT}\b")


def _code_files():
    for root in CODE_ROOTS:
        p = REPO_ROOT / root
        if p.is_file():
            yield p
            continue
        for f in p.rglob("*"):
            if not f.is_file() or f.suffix not in {".rs", ".go", ".sh", ".yml", ".yaml", ".conf", ".py", ".env", ".example", ""}:
                continue
            if f.name.endswith("_test.go") or "/tests/" in str(f) or "/target/" in str(f):
                continue
            yield f


def _code_lines(path):
    """(lineno, line) with the line comment stripped; a Rust file's
    `#[cfg(test)]` module is fixtures, not renders, and is not read."""
    for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if path.suffix == ".rs" and line.strip() == "#[cfg(test)]":
            return
        code = re.split(r"(^|\s)//|(^|\s)#", line, maxsplit=1)[0]
        yield i, code


def test_no_plaintext_cache_url_is_rendered_anywhere():
    hits = []
    for f in _code_files():
        for i, code in _code_lines(f):
            if PLAIN_URL.search(code):
                hits.append(f"{f.relative_to(REPO_ROOT)}:{i}: {code.strip()}")
    assert not hits, "a plaintext model-cache URL (:8083) is rendered or defaulted in code:\n" + "\n".join(hits)


def test_provision_renders_the_https_url():
    src = (REPO_ROOT / "noo-cli/src/commands/provision.rs").read_text()
    renders = re.findall(r'"noo_model_cache_url",\s*format!\("([^"]+)"\)', src)
    assert renders, "provision.rs no longer renders noo_model_cache_url — update this test"
    for r in renders:
        assert r == "https://{ctrl_host}:8443", f"provision renders NOO_MODEL_CACHE_URL as {r!r}"


def test_the_agent_refuses_a_plaintext_url_rather_than_rewriting_it():
    src = (REPO_ROOT / "node-agent-go/internal/preseed/preseed.go").read_text()
    code = "\n".join(re.split(r"(^|\s)//", line, maxsplit=1)[0] for line in src.splitlines())
    assert "legacyPlainPort" not in code, "the phase-1 rewrite constant is back"
    assert 'u.Scheme = "https"' not in code, "preseed.go rewrites a plaintext URL instead of refusing it"
    assert 'if u.Scheme != "https"' in code, "the scheme check is gone"
    assert re.search(r'RefusalScope\s*=\s*"model_cache_url"', code), "the refusal scope the verify row reads is gone"
