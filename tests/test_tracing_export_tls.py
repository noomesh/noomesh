# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Spans leave over TLS checked against the cluster CA, or not at all.

`init_tracing` used to pass `insecure=not NOO_TLS_CA`: an unset variable
meant plaintext export (followup 510). The OpenTelemetry packages are an
optional extra and not installed here, so these replace the names
`tracing.py` imports with recorders and check what the exporter is built
with.
"""

from __future__ import annotations

import types
from pathlib import Path

import pytest

import noomesh.tracing as tracing


class _Recorder:
    def __init__(self) -> None:
        self.exporters: list[dict] = []
        self.roots: list[bytes] = []


@pytest.fixture
def otel(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Recorder:
    rec = _Recorder()

    def exporter(**kw):
        rec.exporters.append(kw)
        return object()

    def creds(root_certificates=None):
        rec.roots.append(root_certificates)
        return ("creds", root_certificates)

    provider = types.SimpleNamespace(add_span_processor=lambda p: None)
    monkeypatch.setattr(tracing, "OTEL_AVAILABLE", True)
    monkeypatch.setattr(tracing, "_initialized", False)
    monkeypatch.setattr(tracing, "_tracer", None)
    monkeypatch.setattr(tracing, "OTLPSpanExporter", exporter, raising=False)
    monkeypatch.setattr(tracing, "grpc", types.SimpleNamespace(ssl_channel_credentials=creds), raising=False)
    monkeypatch.setattr(tracing, "TracerProvider", lambda resource=None: provider, raising=False)
    monkeypatch.setattr(tracing, "BatchSpanProcessor", lambda e: e, raising=False)
    monkeypatch.setattr(tracing, "Resource", types.SimpleNamespace(create=lambda d: d), raising=False)
    monkeypatch.setattr(
        tracing,
        "trace",
        types.SimpleNamespace(set_tracer_provider=lambda p: None, get_tracer=lambda n: "tracer"),
        raising=False,
    )
    # No CA anywhere unless a test puts one there.
    monkeypatch.setattr("noomesh.tls_ca.CONTAINER_CA_PATHS", ())
    monkeypatch.delenv("NOO_TLS_CA", raising=False)
    monkeypatch.setenv("NOO_PKI_DIR", str(tmp_path / "no-pki"))
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4317")
    return rec


def test_no_ca_means_no_export_not_plaintext(otel: _Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    # The old switch must not bring plaintext back either.
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
    assert tracing.init_tracing("svc") is False
    assert otel.exporters == [], "an exporter was built with no CA to check the collector against"


def test_an_http_endpoint_is_refused(otel: _Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_bytes(b"CA")
    monkeypatch.setenv("NOO_TLS_CA", str(ca))
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "HTTP://collector:4317")
    assert tracing.init_tracing("svc") is False
    assert otel.exporters == []


def test_the_exporter_verifies_against_the_cluster_ca(otel: _Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\ncluster\n")
    monkeypatch.setenv("NOO_TLS_CA", str(ca))
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
    assert tracing.init_tracing("svc") is True
    assert len(otel.exporters) == 1
    kw = otel.exporters[0]
    assert kw["insecure"] is False, kw
    assert kw["credentials"] == ("creds", ca.read_bytes()), "the exporter does not check the collector against the cluster CA"
    assert kw["endpoint"] == "https://collector:4317"
