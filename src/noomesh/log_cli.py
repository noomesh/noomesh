# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI sub-app for log aggregation — ``noo logs``."""

from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from .cli_utils import cli_auth_headers, cli_client_cert, cli_http_verify, console, get_gateway_url, is_json_output, output_json, print_error, print_info, run_async

logs_app = typer.Typer(
    help="[dim]Log aggregation[/]",
    rich_markup_mode="rich",
)

_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", timeout: float = 10.0, **kw):
    import httpx

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=cli_http_verify(),
        cert=cli_client_cert(),
        headers=cli_auth_headers(),
    ) as c:
        fn = {"GET": c.get, "POST": c.post}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@logs_app.command()
def containers(
    node: Optional[str] = typer.Option(None, "--node", "-n", help="Filter by node ID"),
) -> None:
    """List containers across the cluster."""
    run_async(_containers_async(node))


async def _containers_async(node: Optional[str]) -> None:
    params = {}
    if node:
        params["node_id"] = node

    try:
        data = await _fetch("/api/logs/containers", timeout=15.0, params=params)
    except Exception as e:
        print_error(f"Failed to list containers: {e}")
        return

    items = data.get("containers", [])
    if is_json_output():
        output_json(data)
        return
    if not items:
        print_info("No containers found.")
        return

    table = Table(title="Cluster Containers")
    table.add_column("Node", style="cyan")
    table.add_column("Container", style="bold")
    table.add_column("Status")
    table.add_column("Image", style="dim")

    for c in items:
        status_style = "green" if c.get("status") == "running" else "yellow"
        table.add_row(
            c.get("node_hostname") or c.get("node_id", "?"),
            c.get("name", "?"),
            f"[{status_style}]{c.get('status', '?')}[/{status_style}]",
            c.get("image", ""),
        )

    console.print(table)


@logs_app.command()
def tail(
    container: str = typer.Argument(..., help="Container name or ID"),
    node: Optional[str] = typer.Option(None, "--node", "-n", help="Node ID"),
    lines: int = typer.Option(200, "--lines", "-l", help="Number of log lines"),
) -> None:
    """Fetch recent logs from a container."""
    run_async(_tail_async(container, node, lines))


async def _tail_async(container: str, node: Optional[str], lines: int) -> None:
    if node:
        url_path = f"/api/logs/node/{node}/{container}"
    else:
        # Try to find the container on any node
        found = await _find_container(container)
        if not found:
            print_error(f"Container '{container}' not found on any node.")
            return
        node_id = found["node_id"]
        cname = found["name"]
        url_path = f"/api/logs/node/{node_id}/{cname}"

    try:
        data = await _fetch(url_path, timeout=30.0, params={"tail": lines})
    except Exception as e:
        print_error(f"Failed to fetch logs: {e}")
        return

    log_lines = data.get("logs", [])
    if not log_lines:
        print_info("No log output.")
        return

    for line in log_lines:
        console.print(line, highlight=False)


async def _find_container(name: str) -> Optional[dict]:
    """Find a container by name across all nodes."""
    try:
        data = await _fetch("/api/logs/containers", timeout=15.0)
    except Exception:
        return None

    for c in data.get("containers", []):
        if c.get("name") == name or c.get("id") == name:
            return c
    # Partial match
    for c in data.get("containers", []):
        if name in (c.get("name") or ""):
            return c
    return None


@logs_app.command()
def query(
    logql: str = typer.Argument(..., help="LogQL query string"),
    limit: int = typer.Option(100, "--limit", "-l", help="Max log lines"),
) -> None:
    """Run a LogQL query against Loki."""
    run_async(_query_async(logql, limit))


async def _query_async(logql: str, limit: int) -> None:
    try:
        data = await _fetch("/api/logs/query", timeout=30.0, params={"query": logql, "limit": limit})
    except Exception as e:
        print_error(f"LogQL query failed: {e}")
        return

    # Parse Loki query_range response
    results = data.get("data", {}).get("result", [])
    if not results:
        print_info("No results.")
        return

    for stream in results:
        labels = stream.get("stream", {})
        label_str = ", ".join(f"{k}={v}" for k, v in labels.items())
        console.print(f"\n[bold cyan]{{{label_str}}}[/bold cyan]")
        for ts, line in stream.get("values", []):
            console.print(line, highlight=False)


@logs_app.command()
def status() -> None:
    """Check log aggregation system status."""
    run_async(_status_async())


async def _status_async() -> None:
    try:
        data = await _fetch("/api/logs/status")
    except Exception as e:
        print_error(f"Failed to check status: {e}")
        return

    if is_json_output():
        output_json(data)
        return

    table = Table(title="Log Aggregation Status")
    table.add_column("Component", style="bold")
    table.add_column("Status")

    loki_status = "[green]healthy[/green]" if data.get("loki_ready") else "[red]unavailable[/red]"
    table.add_row("Loki", loki_status)
    table.add_row("Loki URL", data.get("loki_url") or "[dim]not configured[/dim]")
    registry_status = "[green]available[/green]" if data.get("node_registry_available") else "[red]unavailable[/red]"
    table.add_row("Node Registry", registry_status)

    console.print(table)
