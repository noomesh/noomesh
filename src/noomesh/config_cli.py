# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for runtime configuration (noo config ...)."""
from __future__ import annotations

from . import json_fast as _json
from pathlib import Path
from typing import Optional

import httpx
import typer

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
    print_success,
    run_async,
)
from .config import load_config

config_app = typer.Typer(
    help="[bold]Configuration[/] — view and update runtime config",
    rich_markup_mode="rich",
)
_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", **kw):
    async with httpx.AsyncClient(
        timeout=10.0,
        verify=cli_http_verify(),
        cert=cli_client_cert(),
        headers=cli_auth_headers(),
    ) as c:
        fn = {"GET": c.get, "POST": c.post, "DELETE": c.delete, "PUT": c.put}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@config_app.command("show")
def show(
    config: Optional[Path] = typer.Option(None, help="Path to config YAML."),
):
    """Show local configuration (from YAML file)."""
    config_obj, resolved = load_config(config)
    if is_json_output():
        output_json({"config_path": str(resolved) if resolved else None, **config_obj.model_dump()})
        return
    console.print(f"config_path: {resolved or 'none'}")
    console.print_json(data=config_obj.model_dump())


@config_app.command("get")
def get(
    section: Optional[str] = typer.Argument(None, help="Config section (e.g. 'cluster', 'rag')"),
):
    """Get runtime configuration from the gateway."""
    run_async(_get_async(section))


async def _get_async(section: Optional[str]):
    path = f"/api/config/{section}" if section else "/api/config"
    try:
        data = await _fetch(path)
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    if is_json_output():
        output_json(data)
    else:
        console.print_json(data=data)


@config_app.command("set")
def set_config(
    section: str = typer.Argument(..., help="Config section to update"),
    updates: str = typer.Argument(..., help="JSON string of key-value updates"),
):
    """Update runtime configuration on the gateway."""
    try:
        parsed = _json.loads(updates)
    except _json.JSONDecodeError:
        print_error("Invalid JSON in updates argument")
        raise typer.Exit(1)
    confirm_destructive("Update config section", section)
    run_async(_set_async(section, parsed))


async def _set_async(section: str, updates: dict):
    try:
        data = await _fetch(f"/api/config/{section}", method="PUT", json=updates)
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    msg = data.get("message", f"Updated {section}") if isinstance(data, dict) else str(data)
    print_success(msg)


@config_app.command("export-effective")
def export_effective(
    output: str = typer.Option(None, "--output", "-o", help="Write to file instead of stdout"),
) -> None:
    """📸 Export the EFFECTIVE runtime configuration as YAML.

    Renders what the running system is actually configured to do —
    builtin defaults + YAML seed + DB overrides merged — for review,
    diffing, or committing as a deliberate snapshot. This is an EXPORT,
    not a sync: the DB never writes back to noomesh.yaml; promote
    pieces of this snapshot into the seed file by hand when you want a
    new baseline.
    """
    from datetime import datetime, timezone

    import httpx
    import yaml

    from .cli_utils import cli_httpx_kwargs, get_gateway_url

    gw = get_gateway_url()

    def _get(path: str) -> dict:
        try:
            r = httpx.get(f"{gw}{path}", timeout=15, **cli_httpx_kwargs())
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    autonomy = _get("/api/autonomy/status")
    kb_rules = _get("/api/kb/rules")
    kb_grants = _get("/api/kb/grants")

    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "Effective runtime config (builtins + YAML seed + DB overrides). "
                "Export, not seed — promote into noomesh.yaml deliberately.",
        "autonomy": {
            "enabled": autonomy.get("running"),
            "locations_enabled": autonomy.get("locations_enabled"),
            "locations": autonomy.get("locations", autonomy),
        },
        "kb": {
            "source_rules_db": kb_rules.get("rules", kb_rules),
            "role_grants": kb_grants.get("grants", kb_grants),
        },
    }
    rendered = yaml.safe_dump(snapshot, sort_keys=False, allow_unicode=True)
    if output:
        from pathlib import Path
        Path(output).write_text(rendered)
        console.print(f"[green]Effective config written to {output}[/]")
    else:
        console.print(rendered)
