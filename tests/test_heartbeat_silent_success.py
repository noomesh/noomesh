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
