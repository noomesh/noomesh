# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for the Heartbeat Scheduler (noo heartbeat ...)."""
from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from .cli_utils import (
    cli_auth_headers,
    cli_client_cert,
    cli_http_verify,
    confirm_destructive,
    console,
    get_gateway_url,
    is_json_output,
    output_json,
    print_error,
    print_info,
    print_success,
    print_warning,
    run_async,
)

heartbeat_app = typer.Typer(
    help="[dim]Heartbeat cron scheduler for automated tasks[/]",
    rich_markup_mode="rich",
)

_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", timeout: float = 10.0, **kw):
    import httpx

    async with httpx.AsyncClient(timeout=timeout, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        fn = {"GET": c.get, "POST": c.post, "DELETE": c.delete, "PUT": c.put}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@heartbeat_app.command("list")
def heartbeat_list() -> None:
    """List all heartbeat tasks."""
    run_async(_list_async())


async def _list_async() -> None:
    try:
        data = await _fetch("/api/heartbeat/tasks")
    except Exception as e:
        print_error(f"Failed to fetch tasks: {e}")
        return

    tasks = data.get("tasks", data if isinstance(data, list) else [])
    if is_json_output():
        output_json(data)
        return
    if not tasks:
        print_info("No heartbeat tasks configured.")
        return

    table = Table(title="Heartbeat Tasks")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Schedule")
    table.add_column("Action")
    table.add_column("Enabled")
    table.add_column("Last Run")
    table.add_column("Next Run")

    for t in tasks:
        enabled = "[green]yes[/]" if t.get("enabled") else "[red]no[/]"
        last = t.get("last_run", "-") or "-"
        if isinstance(last, str) and len(last) > 19:
            last = last[:19]
        nxt = t.get("next_run", "-") or "-"
        if isinstance(nxt, str) and len(nxt) > 19:
            nxt = nxt[:19]
        table.add_row(
            t.get("id", "?"),
            t.get("name", "?"),
            t.get("schedule", "?"),
            t.get("action", "?"),
            enabled,
            last,
            nxt,
        )

    console.print(table)


@heartbeat_app.command("add")
def heartbeat_add(
    name: str = typer.Argument(..., help="Task name."),
    schedule: str = typer.Argument(..., help="Cron expression (e.g. '0 8 * * *')."),
    action: str = typer.Option("custom_prompt", help="Action: daily_briefing, cluster_health, rag_reindex, memory_cleanup, custom_prompt."),
    prompt: Optional[str] = typer.Option(None, help="Prompt text for custom_prompt action."),
    channel: Optional[str] = typer.Option(None, help="Channel to notify (e.g. telegram)."),
    recipient: Optional[str] = typer.Option(None, help="Recipient ID for the channel."),
) -> None:
    """Add a new heartbeat task."""
    run_async(_add_async(name, schedule, action, prompt, channel, recipient))


async def _add_async(
    name: str,
    schedule: str,
    action: str,
    prompt: Optional[str],
    channel: Optional[str],
    recipient: Optional[str],
) -> None:
    config = {}
    if prompt:
        config["prompt"] = prompt

    payload = {
        "name": name,
        "schedule": schedule,
        "action": action,
        "config": config,
        "channels": [channel] if channel else [],
        "recipients": [recipient] if recipient else [],
        "enabled": True,
    }

    try:
        result = await _fetch("/api/heartbeat/tasks", method="POST", json=payload)
        print_success(f"Task added: {result.get('id', '?')} -- {name}")
    except Exception as e:
        print_error(f"Failed to add task: {e}")


@heartbeat_app.command("remove")
def heartbeat_remove(
    task_id: str = typer.Argument(..., help="Task ID to remove."),
) -> None:
    """Remove a heartbeat task."""
    confirm_destructive("remove heartbeat task", task_id)
    run_async(_remove_async(task_id))


async def _remove_async(task_id: str) -> None:
    try:
        await _fetch(f"/api/heartbeat/tasks/{task_id}", method="DELETE")
        print_success(f"Task {task_id} removed.")
    except Exception as e:
        print_error(f"Failed to remove task: {e}")


@heartbeat_app.command("run")
def heartbeat_run_now(
    task_id: str = typer.Argument(..., help="Task ID to run immediately."),
) -> None:
    """Run a heartbeat task immediately."""
    run_async(_run_async(task_id))


async def _run_async(task_id: str) -> None:
    with console.status("Running task..."):
        try:
            result = await _fetch(
                f"/api/heartbeat/tasks/{task_id}/run",
                method="POST",
                timeout=120.0,
            )
        except Exception as e:
            print_error(f"Failed to run task: {e}")
            return

    status = result.get("status", "?")
    text = result.get("result_text", "")
    duration = result.get("duration_ms", 0)

    if status == "success":
        print_success(f"Task completed in {duration}ms")
    else:
        print_warning(f"Task finished with status: {status}")

    if text:
        console.print(text)


@heartbeat_app.command("history")
def heartbeat_history(
    task_id: Optional[str] = typer.Option(None, help="Filter by task ID."),
    limit: int = typer.Option(20, help="Max records to show."),
) -> None:
    """Show heartbeat run history."""
    run_async(_history_async(task_id, limit))


async def _history_async(task_id: Optional[str], limit: int) -> None:
    params: dict = {"limit": limit}
    if task_id:
        params["task_id"] = task_id

    try:
        data = await _fetch("/api/heartbeat/history", params=params)
    except Exception as e:
        print_error(f"Failed to fetch history: {e}")
        return

    records = data.get("runs", []) if isinstance(data, dict) else data
    if is_json_output():
        output_json(data)
        return
    if not records:
        print_info("No run history found.")
        return

    table = Table(title="Heartbeat Run History")
    table.add_column("Run ID", style="dim")
    table.add_column("Task")
    table.add_column("Action")
    table.add_column("Status")
    table.add_column("Duration")
    table.add_column("Started")

    for r in records:
        status = r.get("status", "?")
        status_styled = {
            "success": "[green]success[/]",
            "error": "[red]error[/]",
            "running": "[yellow]running[/]",
        }.get(status, status)

        started = r.get("started_at", "-") or "-"
        if isinstance(started, str) and len(started) > 19:
            started = started[:19]

        table.add_row(
            r.get("run_id", "?"),
            r.get("task_name", "?"),
            r.get("action", "?"),
            status_styled,
            f"{r.get('duration_ms', 0)}ms",
            started,
        )

    console.print(table)


@heartbeat_app.command("status")
def heartbeat_status() -> None:
    """Show heartbeat scheduler status."""
    run_async(_status_async())


async def _status_async() -> None:
    try:
        data = await _fetch("/api/heartbeat/status")
    except Exception as e:
        print_error(f"Failed to fetch status: {e}")
        return

    if is_json_output():
        output_json(data)
        return

    running = data.get("running", False)
    enabled = data.get("enabled", False)
    # None means the gateway could not determine it — do not render that as "no".
    croniter_ok = data.get("croniter_available")
    task_count = data.get("task_count", 0)
    interval = data.get("check_interval_seconds", 60)
    recent = data.get("recent_runs", 0)

    status_str = "[green]running[/]" if running else "[red]stopped[/]"
    enabled_str = "[green]yes[/]" if enabled else "[red]no[/]"
    if croniter_ok is None:
        croniter_str = "[dim]unknown[/]"
    else:
        croniter_str = "[green]yes[/]" if croniter_ok else "[red]no[/]"

    console.print(f"  Scheduler: {status_str}")
    console.print(f"  Enabled: {enabled_str}")
    console.print(f"  Croniter: {croniter_str}")
    console.print(f"  Tasks: {task_count}")
    console.print(f"  Check interval: {interval}s")
    console.print(f"  Recent runs: {recent}")

    if not croniter_ok:
        print_warning("Install croniter: pip install croniter")
