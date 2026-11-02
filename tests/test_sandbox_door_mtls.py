# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The sandbox door serves mTLS (mTLS doors phase 1, i77).

Until this change `noo-sandbox` — the executor for model-written code —
answered plain `http://sandbox:9000` on its network, with no TLS and no
caller identity; it was a named exception in the plaintext scanner's ALLOW
list. Now uvicorn terminates TLS itself with the sandbox's own cluster leaf
and REQUIRES a cluster-CA client certificate (`--ssl-cert-reqs 2`), the same
native-listener shape vLLM runs (no stunnel sidecar: the server already
speaks TLS). What this pins:

  1. compose: `sandbox` and `sandbox-extra` run that listener, mount only the
     CA and their own leaf read-only, publish no port, and health-check over
     https with the CA and a client certificate (never CERT_NONE);
  2. every caller's default (`NOO_SANDBOX_URL`, base + overlays) is https;
  3. the plaintext scanner has no sandbox exemption left;
  4. the flags, fed through uvicorn's own CLI parser, make a server that
     refuses a client with no certificate in the handshake and serves one
     that presents a CA-signed leaf — the real behaviour, not a string match;
  5. the key's mount point is outside the per-call bwrap jail.

The noo-cli row `noo cluster verify --controller` → `sandbox listener` is
the runtime half (`cluster_verify.rs::sandbox_listener_check`).
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
import yaml

from tests._compose_projection import full_projection

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"
SANDBOXES = ("sandbox", "sandbox-extra")
LEAF = "/tls/services/sandbox"


def _raw_services() -> dict:
    # Plain safe_load resolves the YAML anchors sandbox-extra reuses.
    return yaml.safe_load(COMPOSE.read_text())["services"]


def _flag(cmd: list[str], name: str) -> str | None:
    return cmd[cmd.index(name) + 1] if name in cmd else None


@pytest.mark.parametrize("name", SANDBOXES)
def test_the_listener_requires_a_client_certificate(name):
    svc = _raw_services()[name]
    cmd = [str(c) for c in svc["command"]]
    assert cmd[:4] == ["python", "-m", "uvicorn", "noomesh.sandbox.app:app"], cmd
    assert _flag(cmd, "--ssl-certfile") == f"{LEAF}/service.crt"
    assert _flag(cmd, "--ssl-keyfile") == f"{LEAF}/service.key"
    assert _flag(cmd, "--ssl-ca-certs") == "/tls/ca.crt"
    # 2 = ssl.CERT_REQUIRED; 1 (OPTIONAL) would admit a caller with none.
    assert _flag(cmd, "--ssl-cert-reqs") == "2"
    assert _flag(cmd, "--port") == "9000"


@pytest.mark.parametrize("name", SANDBOXES)
def test_only_the_ca_and_its_own_leaf_are_mounted_read_only(name):
    vols = [str(v) for v in _raw_services()[name]["volumes"]]
    assert vols == [
        "${NOO_PKI_DIR:-./.pki-placeholder}/ca.crt:/tls/ca.crt:ro",
        "${NOO_PKI_DIR:-./.pki-placeholder}/services/sandbox:/tls/services/sandbox:ro",
    ], vols


@pytest.mark.parametrize("name", SANDBOXES)
def test_no_published_port(name):
    svc = _raw_services()[name]
    assert "ports" not in svc, f"{name} publishes {svc.get('ports')}: the door is noo-sandbox only"
    assert [str(p) for p in _raw_services()["sandbox"].get("expose", [])] == ["9000"]


@pytest.mark.parametrize("name", SANDBOXES)
def test_the_healthcheck_dials_the_door_with_ca_and_client_cert(name):
    test = " ".join(_raw_services()[name]["healthcheck"]["test"])
    assert "https://localhost:9000/health" in test
    assert "cafile='/tls/ca.crt'" in test
    assert f"load_cert_chain('{LEAF}/service.crt','{LEAF}/service.key')" in test
    assert "CERT_NONE" not in test and "check_hostname=False" not in test
    assert "http://" not in test


@pytest.mark.parametrize("name", SANDBOXES)
def test_the_healthcheck_runs_as_the_keys_reader_not_root(name):
    # i277c: the check runs as the container's user (root, cap_drop ALL, no
    # CAP_DAC_OVERRIDE) and the key is 0640 to sandbox-server, so as root it
    # could not load the client certificate and the container was unhealthy
    # with a healthy server.
    svc = _raw_services()[name]
    test = svc["healthcheck"]["test"]
    assert svc.get("user") == "root", "the check's uid follows the container's user"
    assert test[:2] == ["CMD", "setpriv"], test[:3]
    assert "--reuid=sandbox-server" in test and "--regid=sandbox-server" in test and "--clear-groups" in test
    assert test[test.index("--") + 1] == "python", test
    # The capabilities it uses to switch are the container's own: nothing added for it.
    assert {"SETUID", "SETGID"} <= set(svc.get("cap_add", []))


def test_every_caller_defaults_to_https():
    services = full_projection()["services"]
    seen = 0
    for name, svc in services.items():
        env = (svc or {}).get("environment") or {}
        if isinstance(env, list):
            env = dict(e.split("=", 1) for e in env if "=" in e)
        val = env.get("NOO_SANDBOX_URL")
        if val is None:
            continue
        seen += 1
        assert val == "${NOO_SANDBOX_URL:-https://sandbox:9000}", f"{name}: {val}"
    assert seen >= 3, f"gateway, worker(s) and trellion carry NOO_SANDBOX_URL; saw {seen}"
    for f in ROOT.glob("docker-compose*.yml"):
        assert "http://sandbox" not in f.read_text(), f"{f.name} still names the plaintext door"


def test_the_plaintext_scanner_has_no_sandbox_exemption():
    from tests import test_gateway_refuses_plaintext as scan

    assert not [k for k in scan.ALLOW if "sandbox" in k[1]], scan.ALLOW


def test_the_key_mount_is_outside_the_exec_jail():
    from noomesh.sandbox.app import RO_PATHS

    assert not any(LEAF.startswith(p.rstrip("/") + "/") or p == "/tls" for p in RO_PATHS), RO_PATHS


# ── the real listener ──────────────────────────────────────────────────────


def _pki(tmp: Path) -> dict[str, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = _dt.datetime.now(_dt.timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def write_key(k, p):
        p.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("t-ca")).issuer_name(name("t-ca"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - _dt.timedelta(minutes=1)).not_valid_after(now + _dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    out = {"ca": tmp / "ca.crt"}
    out["ca"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(cn, eku):
        k = ec.generate_private_key(ec.SECP256R1())
        c = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca.subject)
             .public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - _dt.timedelta(minutes=1)).not_valid_after(now + _dt.timedelta(days=1))
             .add_extension(x509.SubjectAlternativeName(
                 [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
             .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
             .sign(ca_key, hashes.SHA256()))
        (tmp / f"{cn}.crt").write_bytes(c.public_bytes(serialization.Encoding.PEM))
        write_key(k, tmp / f"{cn}.key")
        return tmp / f"{cn}.crt", tmp / f"{cn}.key"

    both = [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
    out["srv_crt"], out["srv_key"] = leaf("sandbox", both)
    out["cli_crt"], out["cli_key"] = leaf("gateway", both)
    return out


async def _health_app(scope, receive, send):
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok"})


def _get(port: int, ctx: ssl.SSLContext) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=30) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            buf = b""
            while chunk := s.recv(4096):
                buf += chunk
            return buf


def test_the_shipped_flags_refuse_a_caller_without_a_certificate(tmp_path):
    uvicorn = pytest.importorskip("uvicorn")
    from uvicorn.main import main as uvicorn_cli

    pki = _pki(tmp_path)
    cmd = [str(c) for c in _raw_services()["sandbox"]["command"]][3:]
    # Through uvicorn's OWN parser: the flags mean what uvicorn says they mean.
    params = uvicorn_cli.make_context("uvicorn", cmd).params
    assert params["ssl_cert_reqs"] == ssl.CERT_REQUIRED
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
        with socket.create_connection(("127.0.0.1", port), timeout=30) as raw:
            raw.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            try:
                reply = raw.recv(4096)
            except OSError:
                reply = b""
            assert not reply.startswith(b"HTTP/1.1 200"), reply
    finally:
        server.should_exit = True
        t.join(timeout=60)
