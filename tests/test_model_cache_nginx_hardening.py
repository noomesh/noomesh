# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The model cache's nginx stays on a line that gets fixes, and its config
stays out of the bug classes nginx has shipped CVEs for.

The model cache is the one nginx we ship (compose `model-cache`). It ran
nginx 1.27.5 (an EOL line) when the 2026-11-18 advisories landed; it now pins
the patched stable line. Two guards keep it that way:

- the pinned version's line must be the supported line declared in
  scripts/third-party-lines.json (one source for every pinned upstream).
  Its re-check date is NOT a CI check: the weekly third-party-scan job opens
  an issue once the date passes, so a new nginx stable line is noticed
  without failing unrelated merges;
- the directives each reachable-class bug needs stay out of our two conf
  files. The reasons are written beside the list in model-cache.nginx.conf.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"
CONFS = [ROOT / "docker/model-cache.nginx.conf", ROOT / "docker/model-cache.locations.conf"]

# The supported nginx line, as declared for the third-party scan job (its
# policy URL and re-check date live there too).
LINES = ROOT / "scripts/third-party-lines.json"

# Directives (or listen parameters) whose presence is the trigger of a
# shipped nginx CVE class; see the header of model-cache.nginx.conf.
BANNED_DIRECTIVES = {
    "http2", "http3", "quic", "rewrite", "try_files", "resolver",
    "ssl_ocsp", "ssl_stapling", "proxy_protocol", "aio", "ssi",
    "dav_methods", "mp4", "slice",
}
BANNED_LISTEN_PARAMS = {"http2", "quic", "proxy_protocol"}


def _statements(path: Path) -> list[list[str]]:
    """Each `;`-terminated statement (and each `name … {` opener) as words,
    comments and quoted strings removed."""
    text = path.read_text()
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)   # strings: no false hits
    text = re.sub(r"#[^\n]*", "", text)
    out = []
    for raw in re.split(r"[;{}]", text):
        words = raw.split()
        if words:
            out.append(words)
    return out


def _nginx_pin() -> tuple[str, str]:
    # the official image from OUR mirror (mirror-images.yml), never Docker Hub
    m = re.search(r"^\s*image:\s*ghcr\.io/noomesh/nginx:(\d+\.\d+\.\d+)-alpine"
                  r"\$\{NOO_IMAGE_DIGEST_NGINX:-@sha256:([0-9a-f]{64})\}\s*$",
                  COMPOSE.read_text(), re.M)
    assert m, "the model-cache must pin ghcr.io/noomesh/nginx:<x.y.z>-alpine by digest"
    return m.group(1), m.group(2)


def test_the_pinned_nginx_is_on_a_line_that_still_gets_fixes():
    version, _digest = _nginx_pin()
    line = ".".join(version.split(".")[:2])
    declared = json.loads(LINES.read_text())["rows"]["nginx"]["line"]
    assert line == declared, (
        f"nginx {version}: the {line} line is not the supported line declared in "
        f"{LINES.name} ({declared}); 1.27 was EOL when the 2026-11-18 advisories "
        "landed. Move the pin, or update the declared line on nginx.org's evidence")


def test_the_pin_is_not_the_eol_build_it_replaced():
    version, digest = _nginx_pin()
    assert not version.startswith("1.27."), version
    assert digest != "65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"


@pytest.mark.parametrize("conf", CONFS, ids=lambda p: p.name)
def test_no_directive_a_shipped_cve_class_needs(conf):
    hits = []
    for words in _statements(conf):
        name = words[0]
        if name in BANNED_DIRECTIVES:
            hits.append(" ".join(words))
        if name == "listen" and BANNED_LISTEN_PARAMS & set(words[1:]):
            hits.append(" ".join(words))
    assert not hits, (
        f"{conf.name}: {hits}: each is the trigger of a shipped nginx CVE class "
        "(see the list at the top of model-cache.nginx.conf); adding one is a reviewed decision")


def test_the_data_plane_keeps_its_tls_posture():
    stmts = [" ".join(w) for c in CONFS for w in _statements(c)]
    assert "ssl_verify_client on" in stmts, "the data plane is mTLS only"
    assert "ssl_session_tickets off" in stmts, "session tickets stay off (CVE-2026-97629 class)"
    assert not any(s.startswith("ssl_session_tickets on") for s in stmts)


def test_the_file_server_refuses_request_bodies():
    stmts = [" ".join(w) for c in CONFS for w in _statements(c)]
    assert "client_max_body_size 1" in stmts, "no client sends the model cache a body: refuse one"
    assert not any(s.startswith("client_max_body_size 0") for s in stmts), "0 means unlimited"


def test_the_guard_reads_real_directives_not_comments(tmp_path):
    f = tmp_path / "x.conf"
    f.write_text('# rewrite in a comment\nreturn 404 "try_files in a string";\nlisten 8443 ssl http2;\nrewrite ^/a /b?x;\n')
    names = [w[0] for w in _statements(f)]
    assert names == ["return", "listen", "rewrite"]
