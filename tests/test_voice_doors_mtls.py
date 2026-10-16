# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The voice doors serve mTLS (mTLS doors phase 2, i77).

Until this change `noo-whisper` (STT) and `noo-piper` (TTS) — the voice
add-on overlay — answered plain `http://noo-whisper:8000` /
`http://noo-piper:8000` on `noo-cluster`, with no TLS and no caller
identity; both were named exceptions in the plaintext scanner's ALLOW list.
Now each uvicorn terminates TLS itself with its OWN cluster leaf and
REQUIRES a cluster-CA client certificate (`--ssl-cert-reqs 2`), the same
native-listener shape the sandbox (phase 1) and vLLM run. What this pins:

  1. the overlay: `whisper` and `piper` run that listener, mount only the CA
     and their own leaf read-only, publish no port, and health-check over
     https with the CA and a client certificate (never CERT_NONE);
  2. no compose file names a plaintext voice door any more;
  3. the plaintext scanner has no voice exemption left, and the gateway's
     compiled defaults are https;
  4. the flags, fed through uvicorn's own CLI parser, make a server that
     refuses a client with no certificate in the handshake and serves one
     that presents a CA-signed leaf — the real behaviour, not a string match.

The gateway half (https defaults, `http://` refused before any dial, the
cluster client for the cluster's names and the public client for a cloud
provider) is pinned in Rust: `tls.rs::door_tests`, `stt_client.rs`,
`tts_client.rs`. The noo-cli row `noo cluster verify --controller` →
`voice listeners` is the runtime half (`cluster_verify.rs::
voice_listeners_check`), which says "voice off — not checked" when the
add-on is off.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
import yaml

from tests.test_sandbox_door_mtls import _get, _health_app, _pki

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "docker-compose.voice.yml"
DOORS = {"whisper": "whisper_server:app", "piper": "piper_server:app"}


def _services() -> dict:
    return yaml.safe_load(OVERLAY.read_text())["services"]


def _flag(cmd: list[str], name: str) -> str | None:
    return cmd[cmd.index(name) + 1] if name in cmd else None


@pytest.mark.parametrize("name", sorted(DOORS))
def test_the_listener_requires_a_client_certificate(name):
    cmd = [str(c) for c in _services()[name]["command"]]
    leaf = f"/tls/services/{name}"
    # The image's own CMD (docker/Dockerfile.<name>) with the TLS flags added.
    assert cmd[:2] == ["uvicorn", DOORS[name]], cmd
    assert _flag(cmd, "--ssl-certfile") == f"{leaf}/service.crt"
    assert _flag(cmd, "--ssl-keyfile") == f"{leaf}/service.key"
    assert _flag(cmd, "--ssl-ca-certs") == "/tls/ca.crt"
    # 2 = ssl.CERT_REQUIRED; 1 (OPTIONAL) would admit a caller with none.
    assert _flag(cmd, "--ssl-cert-reqs") == "2"
    assert _flag(cmd, "--port") == "8000"


@pytest.mark.parametrize("name", sorted(DOORS))
def test_only_the_ca_and_its_own_leaf_are_mounted_read_only(name):
    vols = [str(v) for v in _services()[name]["volumes"]]
    tls = [v for v in vols if "/tls/" in v]
    assert tls == [
        "${NOO_PKI_DIR:-./.pki-placeholder}/ca.crt:/tls/ca.crt:ro",
        f"${{NOO_PKI_DIR:-./.pki-placeholder}}/services/{name}:/tls/services/{name}:ro",
    ], vols
    # Nothing else from the PKI dir: not the other door's leaf, not the gateway's.
    assert [v for v in vols if "NOO_PKI_DIR" in v] == tls, vols


@pytest.mark.parametrize("name", sorted(DOORS))
def test_no_published_port(name):
    svc = _services()[name]
    assert "ports" not in svc, f"{name} publishes {svc.get('ports')}: the door is noo-cluster only"
    assert [str(p) for p in svc.get("expose", [])] == ["8000"]


@pytest.mark.parametrize("name", sorted(DOORS))
def test_the_healthcheck_dials_the_door_with_ca_and_client_cert(name):
    leaf = f"/tls/services/{name}"
    test = " ".join(_services()[name]["healthcheck"]["test"])
    assert "https://localhost:8000/health" in test
    assert "cafile='/tls/ca.crt'" in test
    assert f"load_cert_chain('{leaf}/service.crt','{leaf}/service.key')" in test
    assert "CERT_NONE" not in test and "check_hostname=False" not in test
    assert "http://" not in test


def test_no_compose_file_names_a_plaintext_voice_door():
    for f in ROOT.glob("docker-compose*.yml"):
        text = f.read_text()
        for door in ("noo-whisper", "noo-piper", "whisper:8000", "piper:8000"):
            assert f"http://{door}" not in text, f"{f.name} still names http://{door}"


def test_the_plaintext_scanner_has_no_voice_exemption_and_the_defaults_are_https():
    from tests import test_gateway_refuses_plaintext as scan

    assert not [k for k in scan.ALLOW if "whisper" in k[1] or "piper" in k[1]], scan.ALLOW
    stt = (ROOT / "gateway-rust/src/stt_client.rs").read_text()
    tts = (ROOT / "gateway-rust/src/tts_client.rs").read_text()
    assert 'pub const STT_DEFAULT_URL: &str = "https://noo-whisper:8000";' in stt
    assert 'pub const TTS_DEFAULT_URL: &str = "https://noo-piper:8000";' in tts


@pytest.mark.parametrize("name", sorted(DOORS))
def test_the_shipped_flags_refuse_a_caller_without_a_certificate(name, tmp_path):
    uvicorn = pytest.importorskip("uvicorn")
    from uvicorn.main import main as uvicorn_cli

    pki = _pki(tmp_path)
    cmd = [str(c) for c in _services()[name]["command"]][1:]
    # Through uvicorn's OWN parser: the flags mean what uvicorn says they mean.
    params = uvicorn_cli.make_context("uvicorn", cmd).params
    assert params["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert params["ssl_ca_certs"] == "/tls/ca.crt"
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    config = uvicorn.Config(
        _health_app, host="127.0.0.1", port=port, log_level="warning", lifespan="off",
        ssl_certfile=str(pki["srv_crt"]), ssl_keyfile=str(pki["srv_key"]),
        ssl_ca_certs=str(pki["ca"]), ssl_cert_reqs=params["ssl_cert_reqs"],
    )
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        deadline = time.time() + 10
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        assert server.started, "uvicorn did not start"

        no_cert = ssl.create_default_context(cafile=str(pki["ca"]))
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            body = _get(port, no_cert)
            # TLS 1.3 reports the refusal on the first read; an empty read
            # (the server closed) is a refusal too — only an HTTP answer is not.
            if not body.startswith(b"HTTP/"):
                raise ConnectionError("closed without an answer")

        with_cert = ssl.create_default_context(cafile=str(pki["ca"]))
        with_cert.load_cert_chain(str(pki["cli_crt"]), str(pki["cli_key"]))
        assert _get(port, with_cert).startswith(b"HTTP/1.1 200")

        # Plaintext gets no HTTP answer at all.
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            raw.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            try:
                reply = raw.recv(4096)
            except OSError:
                reply = b""
            assert not reply.startswith(b"HTTP/1.1 200"), reply
    finally:
        server.should_exit = True
        t.join(timeout=10)
