# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""structured_research must reach the gateway and must not report failure as success.

Two regressions from the same 2026-08 incident: `_gateway_url()` defaulted to
127.0.0.1:8080 (correct only while the worker ran inside the gateway process,
dead after an earlier change moved it to its own container), and `run_research`
returned its failure summary as a normal string, so a month of all-connect-
errors runs was recorded as heartbeat successes.
"""
import pytest

from noomesh.pipeline.core import PipelineResult, StepResult
from noomesh.pipeline.llm import _gateway_url
from noomesh.pipeline import research as research_mod


# ── _gateway_url resolution ─────────────────────────────────────────────

def test_gateway_url_prefers_pipeline_override(monkeypatch):
    monkeypatch.setenv("PIPELINE_GATEWAY_URL", "https://override:9999")
    monkeypatch.setenv("NOO_GATEWAY_URL", "https://gateway:8080")
    assert _gateway_url() == "https://override:9999"


def test_gateway_url_falls_back_to_noo_gateway_url(monkeypatch):
    monkeypatch.delenv("PIPELINE_GATEWAY_URL", raising=False)
    monkeypatch.setenv("NOO_GATEWAY_URL", "https://gateway:8080/")
    assert _gateway_url() == "https://gateway:8080"


def test_gateway_url_localhost_last_resort(monkeypatch):
    monkeypatch.delenv("PIPELINE_GATEWAY_URL", raising=False)
    monkeypatch.delenv("NOO_GATEWAY_URL", raising=False)
    monkeypatch.delenv("NOO_TLS_CERT", raising=False)
    monkeypatch.setenv("GATEWAY_PORT", "8080")
    # https whether or not NOO_TLS_CERT is in this process's env: the
    # gateway has no plaintext listener (tests/test_gateway_refuses_plaintext.py).
    assert _gateway_url() == "https://127.0.0.1:8080"


# ── run_research failure propagation ────────────────────────────────────

def _result(ok: bool, ctx=None, steps=()):
    r = PipelineResult(name="research:test", ok=ok, ctx=dict(ctx or {}))
    for label, step_ok in steps:
        r.steps.append(StepResult(step=label, ok=step_ok))
    return r


async def test_run_research_raises_when_pipeline_aborts(monkeypatch):
    async def fake_run_pipeline(pipeline, ctx=None, **kw):
        return _result(False, steps=[("search", True), ("synthesize", False)])

    monkeypatch.setattr(research_mod, "run_pipeline", fake_run_pipeline)
    with pytest.raises(RuntimeError) as ei:
        await research_mod.run_research("test topic")
    msg = str(ei.value)
    assert "produced nothing" in msg
    assert "synthesize:FAIL" in msg


async def test_run_research_ok_returns_summary(monkeypatch):
    ctx = {
        "synthesis": {"takeaways": ["a fact", "another"]},
        "sources": [{"title": "t", "url": "u"}],
        "note_path": "/data/research/research-test-2026-08-27.md",
    }

    async def fake_run_pipeline(pipeline, ctx_in=None, **kw):
        return _result(True, ctx=ctx)

    monkeypatch.setattr(research_mod, "run_pipeline", fake_run_pipeline)
    head = await research_mod.run_research("test topic")
    assert "OK" in head
    assert "2 takeaways" in head
    assert "saved /data/research" in head
