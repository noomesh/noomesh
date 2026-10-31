# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Python request tracing (i359 C1): spans continue the gateway's trace and
leave over TLS against the cluster CA with this container's leaf, or not at
all.

`init_tracing` used to pass `insecure=not NOO_TLS_CA` to an OpenTelemetry
exporter: an unset variable meant plaintext export (followup 510). The SDK
is gone; `noomesh.tracing` writes the gateway's OTLP/HTTP JSON itself. HTTP
is faked at the transport (httpx.MockTransport), not at the call.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

import noomesh.tracing as tracing

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(tracing, "_exporter", None)
    monkeypatch.setattr("noomesh.tls_ca.CONTAINER_CA_PATHS", ())
    yield


def _env(tmp_path: Path, **over: str) -> dict:
    ca, crt, key = tmp_path / "ca.crt", tmp_path / "service.crt", tmp_path / "service.key"
    for p in (ca, crt, key):
        p.write_text("x")
    env = {
        "NOO_TEMPO_OTLP_URL": "https://tempo:4318",
        "NOO_TLS_CA": str(ca),
        "NOO_TLS_CERT": str(crt),
        "NOO_TLS_KEY": str(key),
        "NOO_PKI_DIR": str(tmp_path / "no-pki"),
        # The SDK-era switch must not bring plaintext back.
        "OTEL_EXPORTER_OTLP_INSECURE": "true",
    }
    env.update(over)
    return env


def test_each_missing_piece_means_no_export_never_plaintext(tmp_path: Path) -> None:
    assert tracing.configure(env=_env(tmp_path, NOO_TEMPO_OTLP_URL="")) is False
    assert tracing.configure(env=_env(tmp_path, NOO_TEMPO_OTLP_URL="http://tempo:4318")) is False
    assert tracing.configure(env=_env(tmp_path, NOO_TEMPO_OTLP_URL="HTTP://tempo:4318")) is False
    env = _env(tmp_path)
    del env["NOO_TLS_CA"]
    assert tracing.configure(env=env) is False, "no CA anywhere"
    env = _env(tmp_path)
    del env["NOO_TLS_KEY"]
    assert tracing.configure(env=env) is False, "Tempo requires a client certificate"
    assert tracing._exporter is None


def test_the_exporter_verifies_the_cluster_ca_and_presents_the_leaf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    built = {}
    real = httpx.Client

    def recording(**kw):
        built.update(kw)
        return real(transport=httpx.MockTransport(lambda r: httpx.Response(200)))

    monkeypatch.setattr(httpx, "Client", recording)
    monkeypatch.setattr(tracing._Exporter, "_run", lambda self: None)
    env = _env(tmp_path)
    assert tracing.configure("noo-worker", env=env) is True
    assert built["verify"] == env["NOO_TLS_CA"], built
    assert built["cert"] == (env["NOO_TLS_CERT"], env["NOO_TLS_KEY"]), built
    assert tracing._exporter.url == "https://tempo:4318/v1/traces"


def test_a_span_continues_the_gateways_trace_and_nests() -> None:
    tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    with tracing.span("worker worker.rag.query", traceparent=tp, attrs={"messaging.destination.name": "worker.rag.query"}) as outer:
        assert outer.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert outer.parent == "00f067aa0ba902b7"
        assert tracing.current_trace_id() == outer.trace_id
        with tracing.span("inner") as inner:
            assert (inner.trace_id, inner.parent) == (outer.trace_id, outer.span_id)
    assert tracing.current_trace_id() is None
    for bad in (None, "", "garbage", "00-" + "0" * 32 + "-00f067aa0ba902b7-01", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"):
        with tracing.span("x", traceparent=bad) as s:
            assert s.parent is None and re.fullmatch(r"[0-9a-f]{32}", s.trace_id) and set(s.trace_id) != {"0"}, bad


def test_a_worker_hop_without_a_traceparent_makes_no_span(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    put = []
    monkeypatch.setattr(tracing._Exporter, "_run", lambda self: None)
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert tracing.configure("noo-worker", env=_env(tmp_path), client=client) is True
    monkeypatch.setattr(tracing._exporter, "put", put.append)
    for missing in (None, "", "garbage"):
        ran = []
        with tracing.span("worker worker.x", traceparent=missing, continue_only=True) as s:
            ran.append(1)
            assert s is None and tracing.current_trace_id() is None
        assert ran == [1], "the block still runs"
    assert put == [], "an untraced message made a span (an orphan root trace in Tempo)"
    tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    with tracing.span("worker worker.x", traceparent=tp, continue_only=True) as s:
        assert s is not None and s.parent == "00f067aa0ba902b7"
    assert len(put) == 1


def test_an_exception_marks_the_span_and_propagates() -> None:
    with pytest.raises(RuntimeError):
        with tracing.span("boom") as s:
            raise RuntimeError("x")
    assert s.error is True and s.end_ns >= s.start_ns


def test_the_otlp_json_matches_the_gateways() -> None:
    with tracing.span("worker worker.rag.query", attrs={"n": 3, "flag": True, "subject": "worker.rag.query"}) as s:
        pass
    body = tracing.otlp_body([s], "noo-worker")
    rs = body["resourceSpans"][0]
    assert rs["resource"]["attributes"][0] == {"key": "service.name", "value": {"stringValue": "noo-worker"}}
    sp = rs["scopeSpans"][0]["spans"][0]
    assert re.fullmatch(r"[0-9a-f]{32}", sp["traceId"]) and re.fullmatch(r"[0-9a-f]{16}", sp["spanId"])
    assert "parentSpanId" not in sp
    assert isinstance(sp["startTimeUnixNano"], str) and isinstance(sp["endTimeUnixNano"], str)
    attrs = {a["key"]: a["value"] for a in sp["attributes"]}
    assert attrs["n"] == {"intValue": "3"}
    assert attrs["flag"] == {"stringValue": "True"}, "a bool is not an OTLP int"
    assert sp["status"] == {"code": 1}
    json.dumps(body)


def test_spans_reach_tempo_in_batches_and_a_full_queue_drops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), json.loads(request.content)))
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(tracing._Exporter, "_run", lambda self: None)  # no background thread in the test
    assert tracing.configure("noo-worker", env=_env(tmp_path), client=client) is True
    with tracing.span("one") as s:
        pass
    tracing._exporter.post([s])
    assert seen and seen[0][0] == "https://tempo:4318/v1/traces"
    assert seen[0][1]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"] == s.span_id
    monkeypatch.setattr(tracing, "EXPORT_QUEUE", 1)
    ex = tracing._Exporter("https://tempo:4318/v1/traces", "noo-worker", "ca", ("c", "k"), client=client)
    ex.put(s)
    ex.put(s)
    assert ex.dropped == 1


def test_no_opentelemetry_sdk_surface_in_the_python_tree() -> None:
    hits = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "src" / "noomesh").rglob("*.py")
        if re.search(r"^\s*(from|import)\s+opentelemetry", p.read_text(encoding="utf-8"), re.M)
    ]
    assert not hits, f"an OpenTelemetry SDK import brings OTEL_* env defaults back: {hits}"


def test_the_worker_continues_the_gateways_trace_per_subject() -> None:
    src = (ROOT / "src/noomesh/gateway/worker_pool.py").read_text(encoding="utf-8")
    assert 'tracing.configure("noo-worker")' in src
    assert '(msg.headers or {}).get("traceparent")' in src
    assert re.search(r"with tracing\.span\(\s*f\"worker \{subject\}\",\s*traceparent=traceparent,[^)]*continue_only=True\)", src)
    rust = (ROOT / "gateway-rust/src/bus_principal.rs").read_text(encoding="utf-8")
    assert 'headers.insert("traceparent", tp.as_str());' in rust, "the gateway no longer sends traceparent to workers"
