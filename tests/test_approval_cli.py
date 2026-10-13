# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI tests for `noo approval approve/deny` — the gateway write path.

WP-4a retired the CLI's direct-SQL UPDATE (`_decide_sql`): approve/deny now
POST /api/approval/{id}/decide so every decision goes through gateway auth
and lands in the audit log. These tests pin the CLI side of that contract:
the endpoint/body it sends, the human output, and the exit codes for the
gateway's 404/409 state-machine responses.
"""
from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from noomesh import approval_cli

runner = CliRunner()


def _status_error(status_code: int, error: str) -> httpx.HTTPStatusError:
    """Build the HTTPStatusError `_fetch` raises via raise_for_status()."""
    request = httpx.Request("POST", "http://gw/api/approval/x/decide")
    response = httpx.Response(status_code, json={"error": error}, request=request)
    return httpx.HTTPStatusError(error, request=request, response=response)


@pytest.fixture
def fetch_spy(monkeypatch):
    """Replace the HTTP layer; record (path, method, json body) per call."""
    calls: list[tuple[str, str, dict]] = []

    async def fake_fetch(path, method="GET", **kw):
        calls.append((path, method, kw.get("json", {})))
        return {"status": "approved" if kw.get("json", {}).get("decision") == "approve" else "denied",
                "request_id": path.split("/")[3],
                "resolved_by": "cli-operator"}

    monkeypatch.setattr(approval_cli, "_fetch", fake_fetch)
    return calls


def test_approve_posts_decide_endpoint(fetch_spy):
    result = runner.invoke(approval_cli.approval_app, ["approve", "req-1"])
    assert result.exit_code == 0, result.output
    assert fetch_spy == [("/api/approval/req-1/decide", "POST", {"decision": "approve"})]
    assert "Approved req-1" in result.output


def test_deny_with_reason_sends_reason(fetch_spy):
    result = runner.invoke(
        approval_cli.approval_app, ["deny", "req-2", "--reason", "not allowed"]
    )
    assert result.exit_code == 0, result.output
    assert fetch_spy == [
        ("/api/approval/req-2/decide", "POST", {"decision": "deny", "reason": "not allowed"})
    ]
    assert "Denied req-2" in result.output


def test_deny_without_reason_omits_field(fetch_spy):
    result = runner.invoke(approval_cli.approval_app, ["deny", "req-3"])
    assert result.exit_code == 0, result.output
    assert fetch_spy[0][2] == {"decision": "deny"}


def test_missing_id_404_errors_nonzero(monkeypatch):
    async def fake_fetch(path, method="GET", **kw):
        raise _status_error(404, "approval request 'nope' not found")

    monkeypatch.setattr(approval_cli, "_fetch", fake_fetch)
    result = runner.invoke(approval_cli.approval_app, ["approve", "nope"])
    assert result.exit_code == 1
    assert "not found" in result.output


def test_already_decided_409_errors_nonzero(monkeypatch):
    async def fake_fetch(path, method="GET", **kw):
        raise _status_error(409, "approval request 'req-4' already approved")

    monkeypatch.setattr(approval_cli, "_fetch", fake_fetch)
    result = runner.invoke(approval_cli.approval_app, ["deny", "req-4"])
    assert result.exit_code == 1
    assert "already approved" in result.output


def test_gateway_unreachable_errors_nonzero(monkeypatch):
    async def fake_fetch(path, method="GET", **kw):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(approval_cli, "_fetch", fake_fetch)
    result = runner.invoke(approval_cli.approval_app, ["approve", "req-5"])
    assert result.exit_code == 1
    assert "Failed to reach gateway" in result.output


def test_direct_sql_path_is_gone():
    """The direct-DB write path must stay retired — decisions go through
    the gateway (auth + audit), never a CLI-side UPDATE."""
    assert not hasattr(approval_cli, "_decide_sql")
