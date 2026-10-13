# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for the autonomy engine (noo autonomy ...)."""
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
    is_json_output,
    output_json,
    output_result,
    print_info,
    print_success,
    run_async,
)

autonomy_app = typer.Typer(help="[bold magenta]Autonomy engine[/] monitoring & control", rich_markup_mode="rich")
_gw = get_gateway_url

async def _fetch(path: str, method: str = "GET", **kw):
    async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        resp = await (c.get if method == "GET" else c.post)(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()

@autonomy_app.command()
def status():
    """Show autonomy engine status and locations."""
    run_async(_status_async())

async def _status_async():
    try:
        data = await _fetch("/api/autonomy/status")
    except Exception as e:
        http_fail(e)
    output_result(data, render_table=_render_status)

def _render_status(data):
    tag = "[green]RUNNING[/green]" if data.get("running") else "[red]STOPPED[/red]"
    console.print(f"Engine: {tag}  |  Locations: {data.get('locations_enabled', 0)}/{data.get('locations_total', 0)} enabled  |  Audit: {data.get('audit_entries', 0)}")
    locs = data.get("locations", [])
    if not locs:
        print_info("No locations configured.")
        return
    t = Table(title="Monitoring Locations", show_lines=False)
    for col in ("Name:cyan", "Type:", "Enabled:", "Interval:", "Cooldown:", "Conds:", "Acts:"):
        name, _, style = col.partition(":")
        t.add_column(name, style=style or None)
    for l in locs:
        en = "[green]yes[/green]" if l.get("enabled") else "[red]no[/red]"
        t.add_row(l.get("name",""), l.get("type",""), en, f"{l.get('interval',0)}s",
                  f"{l.get('cooldown',0)}s", str(l.get("conditions",0)), str(l.get("actions",0)))
    console.print(t)

@autonomy_app.command()
def audit(limit: int = typer.Option(20, help="Number of recent entries.")):
    """Show recent autonomous decisions."""
    run_async(_audit_async(limit))

async def _audit_async(limit: int):
    try:
        data = await _fetch("/api/autonomy/audit", params={"limit": limit})
    except Exception as e:
        http_fail(e)
    output_result(data, render_table=_render_audit)

def _render_audit(data):
    entries = data.get("entries", [])
    if not entries:
        print_info("No audit entries yet.")
        return
    t = Table(title="Audit Log", show_lines=False)
    t.add_column("Time", style="dim")
    t.add_column("Location", style="cyan")
    t.add_column("Condition")
    t.add_column("Action", style="yellow")
    for e in entries:
        ts = e.get("timestamp", 0)
        t.add_row(datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "?",
                  e.get("location",""), e.get("condition",""), e.get("action",""))
    console.print(t)

@autonomy_app.command()
def enable():
    """Enable the autonomy engine."""
    run_async(_toggle(True))

@autonomy_app.command()
def disable():
    """Disable the autonomy engine."""
    run_async(_toggle(False))

async def _toggle(enabled: bool):
    ep = "enable" if enabled else "disable"
    try:
        await _fetch(f"/api/autonomy/{ep}", method="POST")
    except Exception as e:
        http_fail(e)
    if is_json_output():
        output_json({"status": "ok", "action": ep, "enabled": enabled})
    else:
        print_success(f"Autonomy engine {'enabled' if enabled else 'disabled'}.")

@autonomy_app.command("locations")
def list_locations():
    """List configured monitoring locations."""
    run_async(_status_async())
