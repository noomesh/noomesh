# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for the proactive agent loop (noo proactive ...)."""
from __future__ import annotations

import datetime

import httpx
import typer
from rich.table import Table
from .cli_utils import (
    cli_auth_headers,
    cli_client_cert,
    cli_http_verify,
    console,
    get_gateway_url,
    http_fail,
    output_result,
    print_info,
    run_async,
)

proactive_app = typer.Typer(
    help="[bold green]Proactive agent[/] loop -- outbound alerts & notifications",
    rich_markup_mode="rich",
)
_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", **kw):
    async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        fn = c.get if method == "GET" else (c.post if method == "POST" else c.delete)
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@proactive_app.command()
def status():
    """Show proactive agent status."""
    run_async(_status_async())


async def _status_async():
    try:
        data = await _fetch("/api/proactive/status")
    except Exception as e:
        http_fail(e)
    output_result(data, render_table=_render_status)


def _render_status(data):
    tag = "[green]RUNNING[/green]" if data.get("running") else "[red]STOPPED[/red]"
    console.print(
        f"Proactive Agent: {tag}  |  "
        f"Rules: {data.get('rules_enabled', 0)}/{data.get('rules_total', 0)} enabled  |  "
        f"History: {data.get('history_entries', 0)} entries"
    )


@proactive_app.command()
def rules():
    """List all proactive rules."""
    run_async(_rules_async())


async def _rules_async():
    try:
        data = await _fetch("/api/proactive/rules")
    except Exception as e:
        http_fail(e)
    output_result(data, render_table=_render_rules)


def _render_rules(data):
    rule_list = data.get("rules", [])
    if not rule_list:
        print_info("No proactive rules configured.")
        return
    t = Table(title="Proactive Rules", show_lines=False)
    t.add_column("ID", style="dim")
    t.add_column("Name", style="cyan")
    t.add_column("Trigger")
    t.add_column("Action", style="yellow")
    t.add_column("Channels")
    t.add_column("Cooldown")
    t.add_column("Enabled")
    for r in rule_list:
        en = "[green]yes[/green]" if r.get("enabled") else "[red]no[/red]"
        trigger = f"{r.get('trigger_type', '')}:{r.get('trigger_pattern', '')}"
        t.add_row(
            r.get("id", ""),
            r.get("name", ""),
            trigger[:30],
            r.get("action_type", ""),
            ", ".join(r.get("channel_targets", [])),
            f"{r.get('cooldown_seconds', 0)}s",
            en,
        )
    console.print(t)


@proactive_app.command()
def history(
    limit: int = typer.Option(20, help="Number of recent entries."),
):
    """Show recent proactive rule firings."""
    run_async(_history_async(limit))


async def _history_async(limit: int):
    try:
        data = await _fetch("/api/proactive/history", params={"limit": limit})
    except Exception as e:
        http_fail(e)
    output_result(data, render_table=_render_history)


def _render_history(data):
    entries = data.get("entries", [])
    if not entries:
        print_info("No proactive firings yet.")
        return
    t = Table(title="Proactive History", show_lines=False)
    t.add_column("Time", style="dim")
    t.add_column("Rule", style="cyan")
    t.add_column("Trigger")
    t.add_column("Channels", style="yellow")
    t.add_column("OK?")
    t.add_column("Message")
    for e in entries:
        ts = e.get("timestamp", 0)
        time_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "?"
        ok = "[green]yes[/green]" if e.get("success") else "[red]no[/red]"
        t.add_row(
            time_str,
            e.get("rule_name", ""),
            e.get("trigger_event", ""),
            ", ".join(e.get("channels_sent", [])) or "-",
            ok,
            (e.get("message", ""))[:60],
        )
    console.print(t)
