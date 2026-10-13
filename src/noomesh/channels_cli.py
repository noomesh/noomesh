# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for channel adapters.

Provides ``noo channels status`` and ``noo channels test`` for inspecting
and testing configured messaging channels.
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from .cli_utils import (
    cli_auth_headers,
    cli_client_cert,
    cli_http_verify,
    console,
    get_gateway_url,
    is_json_output,
    output_json,
    print_error,
    print_success,
    run_async,
)

channels_app = typer.Typer(
    name="channels",
    help="[bold blue]Channel adapters[/bold blue] (WhatsApp, Google Chat)",
    rich_markup_mode="rich",
)

_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", timeout: float = 10.0, **kw):
    import httpx

    async with httpx.AsyncClient(timeout=timeout, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        fn = {"GET": c.get, "POST": c.post}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@channels_app.command("status")
def status(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Show status of all registered channel adapters."""
    run_async(_status_async(gateway))


async def _status_async(gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    with console.status("Fetching channel status..."):
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.get(f"{gw}/api/channels/status")
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            try:
                detail = exc.response.json().get("detail", str(exc))
            except Exception:
                detail = str(exc)
            print_error(detail)
            return
        except Exception as exc:
            print_error(str(exc))
            return

    channels = data.get("channels", {})
    if is_json_output():
        output_json(data)
        return
    if not channels:
        console.print("[dim]No channel adapters registered.[/dim]")
        return

    table = Table(title="Channel Adapters")
    table.add_column("Channel", style="bold")
    table.add_column("Received", justify="right")
    table.add_column("Sent", justify="right")
    table.add_column("Errors", justify="right", style="red")

    for name, info in channels.items():
        stats = info.get("stats", {})
        table.add_row(
            name,
            str(stats.get("received", 0)),
            str(stats.get("sent", 0)),
            str(stats.get("errors", 0)),
        )

    console.print(table)


@channels_app.command("test")
def test(
    channel: str = typer.Argument(..., help="Channel name: whatsapp, google_chat"),
    recipient: str = typer.Argument(..., help="Recipient ID (phone number or space name)"),
    message: str = typer.Option("Hello from PAI!", "--message", "-m", help="Test message"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Send a test message through a channel adapter."""
    run_async(_test_async(channel, recipient, message, gateway))


async def _test_async(channel: str, recipient: str, message: str, gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    with console.status(f"Sending test message via {channel}..."):
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.post(
                    f"{gw}/api/channels/test",
                    json={"channel": channel, "recipient": recipient, "message": message},
                )
                resp.raise_for_status()
                result = resp.json()
        except httpx.HTTPStatusError as exc:
            try:
                detail = exc.response.json().get("detail", str(exc))
            except Exception:
                detail = str(exc)
            print_error(detail)
            return
        except Exception as exc:
            print_error(str(exc))
            return

    if result.get("success"):
        print_success(f"Test message sent via {channel}")
    else:
        print_error(f"Send failed: {result.get('error', 'unknown error')}")
