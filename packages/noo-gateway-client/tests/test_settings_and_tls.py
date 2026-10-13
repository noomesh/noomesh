# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""`GatewaySettings.from_env`: the variables, and TLS that is never off by omission."""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

import pytest

from noo_gateway import GatewaySettings
from noo_gateway.settings import resolve_verify

# A self-signed test CA (openssl req -x509 -newkey ec …), valid as PEM, trusted by nothing.
CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBoDCCAUWgAwIBAgIUSMsRRipyU27vpaKjC7xBhaEawQkwCgYIKoZIzj0EAwIw
JTEjMCEGA1UEAwwabm9vLWdhdGV3YXktY2xpZW50LXRlc3QtY2EwHhcNMjYwOTI4
MTMxMzE2WhcNMzYwOTI1MTMxMzE2WjAlMSMwIQYDVQQDDBpub28tZ2F0ZXdheS1j
bGllbnQtdGVzdC1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBfOnM1OdMBx
v+I6UzC/6rKuzwyo1eN9MUlzGzoe3UeYpTTLArzZzngYyM/sABxLxUf3RY9VTVIK
38NjfN3CFnijUzBRMB0GA1UdDgQWBBQqai4atROfrNAfq5cjAHmzaJ3AcDAfBgNV
HSMEGDAWgBQqai4atROfrNAfq5cjAHmzaJ3AcDAPBgNVHRMBAf8EBTADAQH/MAoG
CCqGSM49BAMCA0kAMEYCIQCqt6JOWxKziLwqsQ8oiZX94cKROAk0b4LJbSxXUwkn
pwIhAOpZXK1ov7UH7zhlLw+6L25iFYICtH3k/I+rkRqSZ84U
-----END CERTIFICATE-----
"""


def test_reads_every_variable(tmp_path: Path) -> None:
    env = {
        "NOO_GATEWAY_URL": "https://gw.local:8443/",
        "NOO_GATEWAY_KEY": "  nk_abc  ",
        "NOO_CONTROLLER_SECRET": "ctl",
        "NOO_CLUSTER_SECRET": "fleet",
        "NODE_ID": "node-7",
    }  # the last three are present and must be ignored
    s = GatewaySettings.from_env(consumer="svc:x", env=env)
    assert s.url == "https://gw.local:8443", "no trailing slash"
    assert s.key == "nk_abc", "stripped"
    assert not any("ctl" == v or "fleet" == v or "node-7" == v for v in vars(s).values())
    with pytest.raises(TypeError):
        GatewaySettings.from_env(consumer="svc:x", hmac_actor="trellion", env=env)  # type: ignore[call-arg]


def test_no_shared_secret_surface_survives() -> None:
    import noo_gateway

    fields = GatewaySettings.__dataclass_fields__
    assert "secret" not in fields and "hmac_actor" not in fields
    s = GatewaySettings(consumer="svc:x")
    assert not hasattr(s, "secret") and not hasattr(s, "hmac_actor")
    assert "secret" not in s.describe() and "hmac_actor" not in s.describe()
    assert not hasattr(noo_gateway, "hmac_token") and "hmac_token" not in noo_gateway.__all__
    import noo_gateway.auth as auth_mod

    assert not hasattr(auth_mod, "hmac_token") and not hasattr(auth_mod, "LANE_HMAC")


def test_the_source_never_names_the_shared_secrets() -> None:
    """Code tokens only: comments and docstrings may say what was retired."""
    import ast
    import io
    import tokenize

    src_root = Path(__file__).resolve().parents[1] / "src"
    files = sorted(src_root.rglob("*.py"))
    assert files, "the scan must find the package source"
    banned = ("NOO_CONTROLLER_SECRET", "NOO_CLUSTER_SECRET", "hmac.new", "import hmac")
    for f in files:
        text = f.read_text()
        tree = ast.parse(text)
        doc_lines: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
                if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                        and isinstance(body[0].value.value, str):
                    doc_lines.update(range(body[0].lineno, (body[0].end_lineno or body[0].lineno) + 1))
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT or tok.start[0] in doc_lines:
                continue
            for word in banned:
                assert word not in tok.string, f"{f.name}:{tok.start[0]} mentions {word}"


def test_defaults_and_blank_means_absent() -> None:
    s = GatewaySettings.from_env(consumer="svc:x", env={"NOO_GATEWAY_KEY": "   ", "NOO_CLUSTER_SECRET": "f"})
    assert s.url == "https://gateway:8080"
    assert s.key is None


def test_overrides_win() -> None:
    s = GatewaySettings.from_env(consumer="svc:evolve", env={"NOO_GATEWAY_URL": "https://a"}, url="https://b")
    assert s.url == "https://b"
    assert s.with_(timeout=3).timeout == 3


def test_no_ca_means_the_system_store_never_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # Only the paths the container would have; none exist on a dev box.
    s = GatewaySettings.from_env(consumer="svc:x", env={})
    assert s.verify is not False, "an unset NOO_TLS_CA must never disable verification"
    assert s.verify is True
    assert resolve_verify({}, consumer="svc:x", default_ca_paths=("/nonexistent/ca.crt",)) is True


def test_a_ca_file_becomes_a_verifying_context(tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_text(CA_PEM)
    s = GatewaySettings.from_env(consumer="svc:x", env={"NOO_TLS_CA": str(ca)})
    assert isinstance(s.verify, ssl.SSLContext)
    assert s.verify.check_hostname is True
    assert s.verify.verify_mode == ssl.CERT_REQUIRED


def test_a_default_ca_path_is_used_when_present(tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_text(CA_PEM)
    v = resolve_verify({}, consumer="svc:x", default_ca_paths=("/nonexistent", str(ca)))
    assert isinstance(v, ssl.SSLContext)


@pytest.mark.parametrize(
    "name", ["NOO_GATEWAY_TLS_VERIFY", "NOO_GATEWAY_TLS_CHECK_HOSTNAME", "NOO_GATEWAY_SHARED_SECRET_FALLBACK"]
)
def test_a_retired_toggle_set_off_is_refused_by_name(name: str, caplog: pytest.LogCaptureFixture) -> None:
    """Verification cannot be turned off and the client has no shared-secret lane.

    The toggles that did either are retired; one still set to its OFF value
    is a refusal naming it, never a silent "verified anyway"."""
    caplog.set_level(logging.ERROR, logger="noo_gateway")
    for off in ("0", "false", " OFF "):
        with pytest.raises(ValueError, match=name):
            GatewaySettings.from_env(consumer="svc:x", env={name: off})
    assert any("gateway_settings_refused" in r.getMessage() for r in caplog.records)
    # Any other value is inert: it no longer means anything, and says nothing.
    for inert in ("", "1", "true", "yes"):
        s = GatewaySettings.from_env(consumer="svc:x", env={name: inert})
        assert s.verify is True


def test_verify_false_cannot_be_constructed() -> None:
    with pytest.raises(ValueError, match="verification"):
        GatewaySettings(consumer="svc:x", verify=False)
    assert "shared_secret_fallback" not in GatewaySettings.__dataclass_fields__


def test_client_cert_only_when_both_files_exist(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("x")
    env = {"NOO_TLS_CERT": str(cert), "NOO_TLS_KEY": str(key)}
    assert GatewaySettings.from_env(consumer="svc:x", env=env).cert is None
    key.write_text("y")
    assert GatewaySettings.from_env(consumer="svc:x", env=env).cert == (str(cert), str(key))


def test_describe_and_repr_carry_no_secret() -> None:
    s = GatewaySettings(consumer="svc:x", key="nk_secret_value")
    text = repr(s) + repr(s.describe()) + str(s.key_fingerprint)
    assert "nk_secret_value" in repr(s), "repr is the dataclass's; describe() is the safe form"
    d = s.describe()
    assert d["key"] == "set"
    assert "nk_secret_value" not in repr(d)
    assert len(s.key_fingerprint or "") == 16 and "nk_secret" not in text.replace(repr(s), "")


def test_a_consumer_is_required() -> None:
    with pytest.raises(ValueError):
        GatewaySettings(consumer="")
