# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for memory system management.

Includes embedding worker control and memory statistics.
"""

from __future__ import annotations

import time
from typing import Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
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
    print_hint,
    print_success,
    print_warning,
    run_async,
)

memory_app = typer.Typer(
    help="🧠 [dim]Memory & embedding management[/]",
    rich_markup_mode="rich",
)

_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", timeout: float = 10.0, **kw):
    import httpx

    async with httpx.AsyncClient(timeout=timeout, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        fn = {"GET": c.get, "POST": c.post, "DELETE": c.delete}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@memory_app.command("embed")
def embed(
    batch_size: int = typer.Option(100, "--batch-size", "-b", help="Records per batch"),
    delay: float = typer.Option(1.0, "--delay", "-d", help="Seconds between batches"),
    max_batches: Optional[int] = typer.Option(None, "--max-batches", "-m", help="Max batches (None = all)"),
    build_graph: bool = typer.Option(False, "--build-graph", "-g", help="Build semantic relationships"),
    threshold: float = typer.Option(0.7, "--threshold", "-t", help="Similarity threshold for relationships"),
    model: Optional[str] = typer.Option(None, "--model", help="Embedding model (default: EMBEDDING_MODEL env)"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL (default: CONTROLLER_URL env)"),
    watch: bool = typer.Option(False, "--watch", "-w", help="Watch progress until complete"),
) -> None:
    """Start background embedding job.

    Idempotent: only processes records without embeddings.
    Safe to run multiple times or schedule via cron.

    Examples:
        noo memory embed --batch-size 100
        noo memory embed --build-graph --watch
        noo memory embed --max-batches 10 --delay 2.0
    """
    run_async(_embed_async(batch_size, delay, max_batches, build_graph, threshold, model, gateway, watch))


async def _embed_async(
    batch_size: int,
    delay: float,
    max_batches: Optional[int],
    build_graph: bool,
    threshold: float,
    model: Optional[str],
    gateway: Optional[str],
    watch: bool,
) -> None:
    gw = gateway or _gw()

    # Override gateway for this request if provided
    import httpx

    with console.status("Starting embedding worker..."):
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.post(
                    f"{gw}/api/memory/embed/start",
                    json={
                        "batch_size": batch_size,
                        "delay_between_batches": delay,
                        "max_batches": max_batches,
                        "build_relationships": build_graph,
                        "similarity_threshold": threshold,
                        "embedding_model": model,
                    },
                )
                resp.raise_for_status()
                result = resp.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            print_error(detail)
            return
        except Exception as e:
            print_error(str(e))
            return

    if result.get("status") == "already_running":
        print_warning("Embedding worker is already running")
    else:
        print_success("Embedding worker started")

    _print_embed_status(result)

    if watch:
        _watch_progress(gateway or _gw())


@memory_app.command("embed-status")
def embed_status(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL (default: CONTROLLER_URL env)"),
    watch: bool = typer.Option(False, "--watch", "-w", help="Watch progress until complete"),
) -> None:
    """Show embedding worker status."""
    run_async(_embed_status_async(gateway, watch))


async def _embed_status_async(gateway: Optional[str], watch: bool) -> None:
    gw = gateway or _gw()
    import httpx

    try:
        async with httpx.AsyncClient(timeout=5.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
            resp = await c.get(f"{gw}/api/memory/embed/status")
            resp.raise_for_status()
            result = resp.json()
    except Exception as e:
        print_error(str(e))
        return

    _print_embed_status(result)

    if watch and result.get("state") == "running":
        _watch_progress(gw)


@memory_app.command("embed-stop")
def embed_stop(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL (default: CONTROLLER_URL env)"),
) -> None:
    """Stop the embedding worker."""
    run_async(_embed_stop_async(gateway))


async def _embed_stop_async(gateway: Optional[str]) -> None:
    gw = gateway or _gw()
    import httpx

    with console.status("Stopping embedding worker..."):
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
                resp = await c.post(f"{gw}/api/memory/embed/stop")
                resp.raise_for_status()
                result = resp.json()
        except Exception as e:
            print_error(str(e))
            return

    print_success("Embedding worker stopped")
    _print_embed_status(result)


@memory_app.command("stats")
def memory_stats(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL (default: CONTROLLER_URL env)"),
) -> None:
    """Show memory system statistics."""
    run_async(_stats_async(gateway))


async def _stats_async(gateway: Optional[str]) -> None:
    gw = gateway or _gw()
    import httpx

    storage = conv_stats = tool_stats_data = None

    async with httpx.AsyncClient(timeout=5.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        try:
            resp = await c.get(f"{gw}/api/memory/storage-stats")
            resp.raise_for_status()
            storage = resp.json()
        except Exception as e:
            print_error(f"Error fetching storage stats: {e}")

        try:
            resp = await c.get(f"{gw}/api/conversations/stats/overview")
            resp.raise_for_status()
            conv_stats = resp.json()
        except Exception:
            pass

        try:
            resp = await c.get(f"{gw}/api/conversations/stats/tools")
            resp.raise_for_status()
            tool_stats_data = resp.json()
        except Exception:
            pass

    if is_json_output():
        output_json({"storage": storage, "conversations": conv_stats, "tools": tool_stats_data})
        return

    if storage:
        console.print("\n[bold cyan]Storage Statistics[/bold cyan]")
        table = Table(show_header=False, box=None)
        table.add_column("Key", style="dim")
        table.add_column("Value")

        table.add_row("Total records", str(storage.get("total_records", 0)))
        table.add_row("Embedded", str(storage.get("embedded_records", 0)))
        table.add_row("Unembedded", f"[yellow]{storage.get('unembedded_records', 0)}[/yellow]")
        table.add_row("Unique users", str(storage.get("unique_users", 0)))
        table.add_row("Embeddings enabled", "Yes" if storage.get("embeddings_enabled") else "No")

        console.print(table)

    if conv_stats:
        console.print("\n[bold cyan]Conversation Statistics (30 days)[/bold cyan]")
        table = Table(show_header=False, box=None)
        table.add_column("Key", style="dim")
        table.add_column("Value")

        table.add_row("Total conversations", str(conv_stats.get("total_conversations", 0)))
        table.add_row("Total messages", str(conv_stats.get("total_messages", 0)))
        table.add_row("Total tool calls", str(conv_stats.get("total_tool_calls", 0)))
        table.add_row("Avg messages/conv", f"{conv_stats.get('avg_messages_per_conversation', 0):.1f}")
        table.add_row("Total tokens in", f"{conv_stats.get('total_tokens_in', 0):,}")
        table.add_row("Total tokens out", f"{conv_stats.get('total_tokens_out', 0):,}")

        console.print(table)

    if tool_stats_data and tool_stats_data.get("tools"):
        console.print("\n[bold cyan]Tool Usage Statistics (30 days)[/bold cyan]")
        table = Table()
        table.add_column("Tool", style="cyan")
        table.add_column("Calls", justify="right")
        table.add_column("Success", justify="right")
        table.add_column("Rate", justify="right")
        table.add_column("Avg Time", justify="right")

        for tool in tool_stats_data["tools"][:10]:
            success_rate = f"{tool.get('success_rate', 0) * 100:.0f}%"
            avg_time = f"{tool.get('avg_execution_ms', 0):.0f}ms" if tool.get('avg_execution_ms') else "-"
            table.add_row(
                tool["name"],
                str(tool.get("total_calls", 0)),
                str(tool.get("successful", 0)),
                success_rate,
                avg_time,
            )

        console.print(table)


@memory_app.command("search")
def memory_search(
    query: str = typer.Argument(..., help="Search query"),
    user: str = typer.Option("anonymous", "--user", "-u", help="User ID"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL (default: CONTROLLER_URL env)"),
) -> None:
    """Search memory for relevant context."""
    run_async(_search_async(query, user, gateway))


async def _search_async(query: str, user: str, gateway: Optional[str]) -> None:
    gw = gateway or _gw()
    try:
        result = await _fetch_with_gw(gw, "/api/memory/search", params={"query": query, "user_id": user})
    except Exception as e:
        print_error(str(e))
        return

    if result.get("context"):
        console.print(f"\n[bold cyan]Relevant Context[/bold cyan] ({result.get('context_length', 0)} chars)\n")
        console.print(result["context"])
    else:
        print_warning("No relevant context found")


@memory_app.command("conversations")
def conversations(
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Filter by user ID"),
    channel: Optional[str] = typer.Option(None, "--channel", "-c", help="Filter by channel"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max conversations"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """List recent conversations."""
    run_async(_conversations_async(user, channel, limit, gateway))


async def _conversations_async(
    user: Optional[str], channel: Optional[str], limit: int, gateway: Optional[str],
) -> None:
    gw = gateway or _gw()
    params: dict = {"limit": limit}
    if user:
        params["user_id"] = user
    if channel:
        params["channel"] = channel

    try:
        data = await _fetch_with_gw(gw, "/api/conversations", params=params)
    except Exception as e:
        print_error(str(e))
        return

    convs = data if isinstance(data, list) else data.get("conversations", [])
    if is_json_output():
        output_json(data)
        return
    if not convs:
        console.print("[dim]No conversations found.[/dim]")
        return

    t = Table(title="Recent Conversations", show_lines=False)
    t.add_column("ID", style="cyan")
    t.add_column("User")
    t.add_column("Channel")
    t.add_column("Messages", justify="right")
    t.add_column("Last Active")
    for c in convs[:limit]:
        t.add_row(
            str(c.get("id", c.get("conversation_id", "?")))[:12],
            c.get("user_id", c.get("user", "-")),
            c.get("channel", "-"),
            str(c.get("message_count", c.get("messages", "?"))),
            str(c.get("last_active", c.get("updated_at", "?")))[:19],
        )
    console.print(t)


@memory_app.command("tool-stats")
def tool_stats(
    days: int = typer.Option(30, "--days", "-d", help="Number of days to look back"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Show tool usage statistics."""
    run_async(_tool_stats_async(days, gateway))


async def _tool_stats_async(days: int, gateway: Optional[str]) -> None:
    gw = gateway or _gw()
    try:
        data = await _fetch_with_gw(gw, "/api/conversations/stats/tools", params={"days": days})
    except Exception as e:
        print_error(str(e))
        return

    tools = data.get("tools", []) if isinstance(data, dict) else data
    if is_json_output():
        output_json(data)
        return
    if not tools:
        console.print("[dim]No tool usage data.[/dim]")
        return

    t = Table(title=f"Tool Usage ({days} days)", show_lines=False)
    t.add_column("Tool", style="cyan")
    t.add_column("Calls", justify="right")
    t.add_column("Success", justify="right")
    t.add_column("Rate", justify="right")
    t.add_column("Avg Time", justify="right")
    for tool in tools[:20]:
        rate = f"{tool.get('success_rate', 0) * 100:.0f}%"
        avg = f"{tool.get('avg_execution_ms', 0):.0f}ms" if tool.get("avg_execution_ms") else "-"
        t.add_row(
            tool.get("name", "?"),
            str(tool.get("total_calls", 0)),
            str(tool.get("successful", 0)),
            rate,
            avg,
        )
    console.print(t)


# ── Helpers ──────────────────────────────────────────────────────────


async def _fetch_with_gw(gw: str, path: str, **kw):
    """Like _fetch but uses an explicit gateway URL (for --gateway overrides)."""
    import httpx

    async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        resp = await c.get(f"{gw}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


def _print_embed_status(status: dict) -> None:
    """Print embedding worker status."""
    state = status.get("state", "unknown")
    stats = status.get("stats", {})

    state_colors = {
        "idle": "dim",
        "running": "green",
        "stopping": "yellow",
        "paused": "yellow",
    }
    color = state_colors.get(state, "white")

    console.print(f"\n[bold]State:[/bold] [{color}]{state}[/{color}]")

    if stats:
        table = Table(show_header=False, box=None)
        table.add_column("Key", style="dim")
        table.add_column("Value")

        table.add_row("Processed", str(stats.get("total_processed", 0)))
        table.add_row("Embedded", f"[green]{stats.get('total_embedded', 0)}[/green]")
        table.add_row("Failed", f"[red]{stats.get('total_failed', 0)}[/red]" if stats.get("total_failed") else "0")
        table.add_row("Relationships", str(stats.get("relationships_created", 0)))

        if stats.get("total_batches"):
            progress = f"{stats.get('current_batch', 0)}/{stats.get('total_batches', 0)}"
            table.add_row("Batch progress", progress)

        if stats.get("duration_seconds"):
            table.add_row("Duration", f"{stats.get('duration_seconds', 0):.1f}s")

        if stats.get("last_error"):
            table.add_row("Last error", f"[red]{stats.get('last_error')}[/red]")

        console.print(table)


def _watch_progress(gateway: str) -> None:
    """Watch embedding progress until complete."""
    import httpx

    print_hint("\nWatching progress (Ctrl+C to stop watching)...\n")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Embedding...", total=100)

            while True:
                try:
                    from .cli_utils import cli_httpx_kwargs
                    response = httpx.get(f"{gateway}/api/memory/embed/status", timeout=5.0, **cli_httpx_kwargs())
                    response.raise_for_status()
                    status = response.json()
                except Exception:
                    time.sleep(2)
                    continue

                state = status.get("state", "idle")
                stats = status.get("stats", {})

                if state not in ("running", "stopping"):
                    break

                total_batches = stats.get("total_batches", 1)
                current_batch = stats.get("current_batch", 0)
                percent = (current_batch / total_batches * 100) if total_batches > 0 else 0

                desc = f"Batch {current_batch}/{total_batches} | Embedded: {stats.get('total_embedded', 0)}"
                progress.update(task, completed=percent, description=desc)

                time.sleep(1)

        print_success("Embedding complete!")
        _print_embed_status(status)

    except KeyboardInterrupt:
        print_hint("\nStopped watching (worker continues in background)")
