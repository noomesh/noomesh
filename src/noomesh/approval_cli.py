# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for the approval queue (noo approval ...)."""
from __future__ import annotations

from typing import Optional

import httpx
import typer
from rich.table import Table

from .cli_utils import cli_client_cert, cli_http_verify, console, get_gateway_url, is_json_output, output_json, print_error, print_success, run_async

approval_app = typer.Typer(
    help="[bold]Approval queue[/] — review pending tool-execution requests",
    rich_markup_mode="rich",
)
_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", **kw):
    from .cli_utils import cli_auth_headers
    async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(),
                                 cert=cli_client_cert(),
                                 headers=cli_auth_headers()) as c:
        fn = {"GET": c.get, "POST": c.post, "DELETE": c.delete, "PUT": c.put}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@approval_app.command("list")
def list_pending():
    """List pending approval requests."""
    run_async(_list_pending_async())


async def _list_pending_async():
    try:
        data = await _fetch("/api/approval/pending")
    except Exception as e:
        print_error(f"Failed to reach gateway: {e}")
        return
    items = data if isinstance(data, list) else data.get("pending", data.get("requests", []))
    if is_json_output():
        output_json(data)
        return
    if not items:
        console.print("[dim]No pending approval requests.[/dim]")
        return
    t = Table(title="Pending Approvals", show_lines=False)
    t.add_column("ID", style="cyan")
    t.add_column("Tool")
    t.add_column("Risk", style="yellow")
    t.add_column("Args")
    t.add_column("Created")
    for r in items:
        t.add_row(
            str(r.get("request_id", r.get("id", "?"))),
            r.get("tool_name", "?"),
            r.get("risk_level", "?"),
            str(r.get("reason") or "")[:60],
            str(r.get("created_at", "?"))[:19],
        )
    console.print(t)


@approval_app.command()
def stats():
    """Show approval queue statistics."""
    run_async(_stats_async())


async def _stats_async():
    try:
        data = await _fetch("/api/approval/stats")
    except Exception as e:
        print_error(f"Failed to reach gateway: {e}")
        return
    if is_json_output():
        output_json(data)
        return
    t = Table(show_header=False, box=None)
    t.add_column("Key", style="dim")
    t.add_column("Value")
    for key in ("total", "approved", "denied", "pending", "timed_out", "expired"):
        if key in data:
            t.add_row(key.capitalize(), str(data[key]))
    console.print(t)


@approval_app.command()
def status():
    """Show exec-approval system status."""
    run_async(_status_async())


async def _status_async():
    try:
        data = await _fetch("/api/exec-approval/status")
    except Exception as e:
        print_error(f"Failed to reach gateway: {e}")
        return
    if is_json_output():
        output_json(data)
    else:
        console.print_json(data=data)


# Approve/deny go through POST /api/approval/{id}/decide, which writes a
# tamper-evident audit row — which the retired direct-SQL UPDATE never did.
# The blocked worker sees the row flip within its ~2s poll.
#
# The gateway requires a NAMED operator here:
# a bare cluster-HMAC bearer (shared by every node, attributable to nobody)
# gets a 403 telling you to run `noo auth login`. Set NOO_TOKEN, or use the
# Rust `noo`, whose stored per-user credential is sent automatically.
# Semantics: 200 pending→decided, 403 unnamed/under-scoped caller,
# 404 unknown id, 409 already decided.

async def _decide_async(request_id: str, decision: str, reason: Optional[str]) -> None:
    body: dict = {"decision": decision}
    if reason:
        body["reason"] = reason
    try:
        data = await _fetch(f"/api/approval/{request_id}/decide", "POST", json=body)
    except httpx.HTTPStatusError as e:
        detail = ""
        try:
            detail = e.response.json().get("error", "")
        except Exception:
            pass
        if e.response.status_code in (404, 409):
            print_error(detail or f"No pending request '{request_id}' (already resolved, or bad id)")
        else:
            print_error(detail or f"Gateway rejected the decision: {e}")
        raise typer.Exit(1)
    except Exception as e:
        print_error(f"Failed to reach gateway: {e}")
        raise typer.Exit(1)
    if is_json_output():
        output_json(data)
    elif decision == "approve":
        print_success(f"Approved {request_id} — the waiting tool call proceeds.")
    else:
        print_success(f"Denied {request_id}")


@approval_app.command()
def approve(request_id: str = typer.Argument(..., help="Approval request ID")):
    """Approve a pending request (via the gateway, audit-logged)."""
    run_async(_decide_async(request_id, "approve", None))


@approval_app.command()
def deny(
    request_id: str = typer.Argument(..., help="Approval request ID"),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Denial reason"),
):
    """Deny a pending request (via the gateway, audit-logged)."""
    run_async(_decide_async(request_id, "deny", reason))
