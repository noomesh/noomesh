# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for browser tool management — ``noo browser status/open/stop``."""
from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from .cli_utils import (
    cli_client_cert,
    cli_http_verify,
    console,
    get_gateway_url,
    is_json_output,
    output_json,
    print_error,
    print_info,
    print_success,
    run_async,
)

browser_app = typer.Typer(
    help="Manage browser automation sessions",
    rich_markup_mode="rich",
)

_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", timeout: float = 10.0, **kw):
    import httpx

    async with httpx.AsyncClient(timeout=timeout, verify=cli_http_verify(), cert=cli_client_cert()) as c:
        fn = {"GET": c.get, "POST": c.post}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@browser_app.command("status")
def browser_status() -> None:
    """Show active browser sessions."""
    run_async(_status_async())


async def _status_async() -> None:
    try:
        data = await _fetch("/api/tools/browser/status", timeout=5.0)
    except Exception as exc:
        print_error(f"Failed to reach gateway: {exc}")
        return

    if is_json_output():
        output_json(data)
        return

    sessions = data.get("sessions", {})
    if not sessions:
        print_info("No active browser sessions.")
        return

    table = Table(title="Active Browser Sessions")
    table.add_column("Session ID", style="cyan")
    table.add_column("Container")
    table.add_column("Node", style="dim")
    table.add_column("Idle (sec)", justify="right")
    table.add_column("URL")

    for sid, info in sessions.items():
        table.add_row(
            sid,
            info.get("container_name", ""),
            info.get("node_id", "local"),
            str(info.get("idle_sec", "")),
            info.get("base_url", ""),
        )

    console.print(table)


@browser_app.command("open")
def browser_open(
    url: str = typer.Argument(..., help="URL to navigate to"),
    node: Optional[str] = typer.Option(None, "--node", "-n", help="Target node ID"),
) -> None:
    """Start a browser session and navigate to a URL."""
    run_async(_open_async(url, node))


async def _open_async(url: str, node: Optional[str]) -> None:
    with console.status("Starting browser session..."):
        try:
            data = await _fetch(
                "/api/tools/browser/action",
                method="POST",
                timeout=60.0,
                json={
                    "action": "navigate",
                    "params": {"url": url, "node_id": node, "screenshot": False},
                },
            )
        except Exception as exc:
            print_error(f"Failed: {exc}")
            return

    if data.get("success"):
        page_data = data.get("data", {})
        print_success(f"Navigated to: {page_data.get('url', url)}")
        print_info(f"Title: {page_data.get('title', 'N/A')}")
        text = page_data.get("text", "")
        if text:
            preview = text[:500]
            if len(text) > 500:
                preview += "..."
            console.print(f"\n[dim]{preview}[/]")
    else:
        print_error(data.get("error", "Unknown error"))


@browser_app.command("stop")
def browser_stop(
    session_id: Optional[str] = typer.Argument(None, help="Session ID (stops all if omitted)"),
) -> None:
    """Stop browser session(s)."""
    run_async(_stop_async(session_id))


async def _stop_async(session_id: Optional[str]) -> None:
    import httpx

    if session_id:
        try:
            await _fetch(
                f"/api/tools/browser/sessions/{session_id}/stop",
                method="POST",
            )
            print_success(f"Session {session_id} stopped.")
        except Exception as exc:
            print_error(f"Failed: {exc}")
        return

    # Stop all sessions
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=cli_http_verify(), cert=cli_client_cert()) as c:
            resp = await c.get(f"{_gw()}/api/tools/browser/sessions")
            resp.raise_for_status()
            sessions = resp.json()
    except Exception as exc:
        print_error(f"Failed to list sessions: {exc}")
        return

    if not sessions:
        print_info("No active sessions.")
        return

    for s in sessions:
        sid = s.get("session_id", "")
        try:
            await _fetch(f"/api/tools/browser/sessions/{sid}/stop", method="POST")
            print_success(f"Stopped session {sid}")
        except Exception as exc:
            print_error(f"Failed to stop {sid}: {exc}")
