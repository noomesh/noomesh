# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A swallowed error must not make a count, a result or a guard lie (i191 D6).

Each test breaks the boundary the action really calls (the HTTP transport, the
session registry, the approval manager) and asserts the failure now shows up.
"""
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from noomesh.gateway.heartbeat import HeartbeatActionExecutor, HeartbeatTask


def _sched(handler) -> HeartbeatActionExecutor:
    s = HeartbeatActionExecutor("http://gw.test")
    s._http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return s


def _task(action: str, **config) -> HeartbeatTask:
    return HeartbeatTask(id="t", name="t", schedule="* * * * *", action=action, config=config)


class _Store:
    async def list_docs(self, limit=20):
        return [{"source_uri": "http://src.test/a", "hash": "old"}]


async def test_knowledge_refresh_raises_when_reingest_post_fails():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "HEAD":
            return httpx.Response(200, headers={"etag": "new"})
        raise httpx.ConnectError("gateway down")

    s = _sched(handler)
    with patch.object(s, "_get_pageindex_store", return_value=_Store()):
        with pytest.raises(RuntimeError, match=r"reingest_failed=1"):
            await s._knowledge_refresh(_task("knowledge_refresh"))


async def test_knowledge_refresh_raises_on_non_200_ingest():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "HEAD":
            return httpx.Response(200, headers={"etag": "new"})
        return httpx.Response(500)

    s = _sched(handler)
    with patch.object(s, "_get_pageindex_store", return_value=_Store()):
        with pytest.raises(RuntimeError, match=r"reingest_failed=1"):
            await s._knowledge_refresh(_task("knowledge_refresh"))


async def test_knowledge_refresh_success_still_returns_summary():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "HEAD":
            return httpx.Response(200, headers={"etag": "new"})
        return httpx.Response(200, json={})

    s = _sched(handler)
    with patch.object(s, "_get_pageindex_store", return_value=_Store()):
        out = await s._knowledge_refresh(_task("knowledge_refresh"))
    assert "1 changed, 1 re-ingestion jobs submitted" in out


RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>Hello</title><link>http://n.test/1</link><description>d</description></item>
</channel></rss>"""


async def test_news_scan_raises_when_ingest_post_fails():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return httpx.Response(200, text=RSS)
        raise httpx.ConnectError("gateway down")

    s = _sched(handler)
    t = _task("news_scan", feeds=["http://feed.test/rss"], ingest=True, summarize=False)
    with pytest.raises(RuntimeError, match=r"ingest_failed=1"):
        await s._news_scan(t)


async def test_thought_experiment_fails_closed_when_session_lookup_throws():
    class _Sessions(dict):
        def values(self):
            raise RuntimeError("registry corrupt")

    coord = SimpleNamespace(_sessions=_Sessions(a=1))
    s = _sched(lambda r: httpx.Response(200))

    def _must_not_run():
        raise AssertionError("maintenance proceeded despite unknown session state")

    with patch("noomesh.gateway.deps.services", SimpleNamespace(coordinator=coord)), \
            patch.object(s, "_get_pageindex_store", side_effect=_must_not_run):
        out = await s._thought_experiment(_task("thought_experiment"))
    assert out.startswith("Skipped: could not determine active sessions")
    assert "registry corrupt" in out


async def test_model_cache_warm_reports_not_checked_when_lookup_fails():
    pulls = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/models/cached":
            raise httpx.ConnectError("gateway down")
        pulls.append(req)
        return httpx.Response(200)

    s = _sched(handler)
    out = await s._model_cache_warm(_task("model_cache_warm", models=[{"model": "m", "node_id": "n"}]))
    assert "not checked" in out
    assert pulls == [], "an unknown cache must not trigger a pull of every model"


async def test_security_audit_does_not_report_clean_when_a_source_errors():
    s = _sched(lambda r: httpx.Response(200, json={}))
    with patch("noomesh.gateway.exec_approval.get_approval_manager", side_effect=RuntimeError("boom")):
        out = await s._security_audit(_task("security_audit"))
    assert "NOT CHECKED" in out and "high_risk_tool_calls" in out
    assert "(incomplete)" in out


async def test_security_audit_skips_loki_when_the_url_is_empty_by_choice(monkeypatch):
    """cluster.monitoring: lean: the launcher exports NOO_LOKI_URL EMPTY. The
    audit must not guess <gateway>:3100 (and warn every run): it skips the
    source, says why once, and the result names the command."""
    import noomesh.gateway.heartbeat as hb

    asked: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        asked.append(str(req.url))
        return httpx.Response(200, json={})

    monkeypatch.setenv("NOO_LOKI_URL", "")
    monkeypatch.setattr(hb, "_LOKI_OFF_NOTED", False)
    infos: list[str] = []
    monkeypatch.setattr(hb.logger, "info", lambda ev, **kw: infos.append(ev))
    warnings: list[str] = []
    monkeypatch.setattr(hb.logger, "warning", lambda ev, **kw: warnings.append(ev))
    s = _sched(handler)
    for _ in range(3):
        out = await s._security_audit(_task("security_audit"))
        assert "log search is off by choice (noo stack monitoring on)" in out, out
        assert "NOT CHECKED" not in out and "auth_failures:" not in out, out
    assert not [u for u in asked if ":3100" in u or "/loki/" in u], asked
    assert infos.count("security_audit_loki_off") == 1, infos
    assert "security_audit_loki_error" not in warnings


async def test_security_audit_with_no_loki_url_at_all_keeps_the_old_guess(monkeypatch):
    """Unset (an older compose) is not lean: the audit still asks <gateway>:3100."""
    asked: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        asked.append(str(req.url))
        return httpx.Response(200, json={"data": {"result": []}})

    monkeypatch.delenv("NOO_LOKI_URL", raising=False)
    s = _sched(handler)
    out = await s._security_audit(_task("security_audit"))
    assert any("gw.test:3100/loki/api/v1/query_range" in u for u in asked), asked
    assert "auth_failures: 0" in out and "off by choice" not in out, out
