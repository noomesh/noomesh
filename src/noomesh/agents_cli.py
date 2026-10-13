# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for multi-agent collaboration.

Provides agent listing and collaborative task execution
via the gateway API.
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
    print_info,
    print_success,
    run_async,
)

agents_app = typer.Typer(
    name="agents",
    help="[bold cyan]Multi-agent[/bold cyan] collaboration",
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


@agents_app.command("list")
def list_agents(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """List available agent roles and their descriptions."""
    run_async(_list_async(gateway))


async def _list_async(gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
            resp = await c.get(f"{gw}/api/agents/roles")
            resp.raise_for_status()
            roles = resp.json()
    except httpx.ConnectError:
        print_info("Gateway unavailable, showing built-in roles:")
        _show_local_roles()
        return
    except Exception as e:
        print_error(f"Failed to fetch agent roles: {e}")
        _show_local_roles()
        return

    if is_json_output():
        output_json(roles)
        return

    table = Table(title="Agent Roles", show_lines=True)
    table.add_column("Role", style="bold cyan")
    table.add_column("Preferred Tools", style="dim")
    table.add_column("Max Loops", justify="right")

    for role in roles:
        table.add_row(
            role["role"],
            ", ".join(role.get("preferred_tools", [])) or "-",
            str(role.get("max_tool_loops", "-")),
        )

    console.print(table)


def _show_local_roles() -> None:
    """Show roles from the local multi_agent module."""
    from .agents import AGENT_SPECS

    table = Table(title="Agent Roles (local)", show_lines=True)
    table.add_column("Role", style="bold cyan")
    table.add_column("Preferred Tools", style="dim")
    table.add_column("Max Loops", justify="right")

    for role, spec in AGENT_SPECS.items():
        table.add_row(
            role.value,
            ", ".join(spec.preferred_tools) or "-",
            str(spec.max_tool_loops),
        )

    console.print(table)


@agents_app.command("collaborate")
def collaborate(
    task: str = typer.Argument(..., help="Task description for the agents"),
    roles: Optional[str] = typer.Option(
        None, "--roles", "-r",
        help="Comma-separated roles (e.g. planner,coder,reviewer). Default: auto-route.",
    ),
    workflow: Optional[str] = typer.Option(
        None, "--workflow", "-w",
        help="Named workflow: [cyan]research[/] | [cyan]plan_code_review[/]",
    ),
    mode: str = typer.Option(
        "auto", "--mode", "-m",
        help="Collaboration mode: [cyan]auto[/] (parallel if possible) | [cyan]sequential[/]",
    ),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Run a multi-agent collaboration on a task.

    By default agents run in parallel with real-time token sharing.
    Use --mode sequential for the classic handoff mode.
    """
    run_async(_collaborate_async(task, roles, workflow, mode, gateway))


async def _collaborate_async(
    task: str,
    roles: Optional[str],
    workflow: Optional[str],
    mode: str,
    gateway: Optional[str],
) -> None:
    import httpx

    gw = gateway or _gw()

    payload: dict = {"task": task, "mode": mode}
    if roles:
        payload["roles"] = [r.strip() for r in roles.split(",")]
    if workflow:
        payload["workflow"] = workflow

    with console.status("Agents collaborating..."):
        try:
            async with httpx.AsyncClient(timeout=300.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as client:
                response = await client.post(
                    f"{gw}/api/agents/collaborate",
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except httpx.ConnectError:
            print_error("Cannot reach gateway. Start services with: noo stack start")
            return
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

    if is_json_output():
        output_json(data)
        return

    # Display results
    results = data.get("results", {})
    for role_name, output in results.items():
        console.print(f"\n[bold cyan]{role_name.upper()}[/bold cyan]")
        console.print(output)

    if data.get("workflow_used"):
        print_info(f"Workflow: {data['workflow_used']}")
    if data.get("mode"):
        print_info(f"Mode: {data['mode']}")

    print_success("Collaboration complete")


# ---------------------------------------------------------------------------
# Peer agent sub-commands  (noo agents peer ...)
# ---------------------------------------------------------------------------

peer_app = typer.Typer(
    name="peer",
    help="[bold cyan]A2A peer agents[/bold cyan] — register, list, and dispatch to external harnesses",
    rich_markup_mode="rich",
)
agents_app.add_typer(peer_app)


@peer_app.command("list")
def peer_list(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
    connected_only: bool = typer.Option(False, "--connected", "-c", help="Show only connected peers"),
) -> None:
    """List registered peer agents (hermes, openclaw, claude-code, etc.)."""
    run_async(_peer_list_async(gateway, connected_only))


async def _peer_list_async(gateway: Optional[str], connected_only: bool) -> None:
    import httpx

    gw = gateway or _gw()
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
            resp = await c.get(f"{gw}/api/agents/peer/")
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        print_error(f"Failed to list peers: {e}")
        return

    peers = data.get("peers", [])
    if connected_only:
        peers = [p for p in peers if p.get("is_connected")]

    if is_json_output():
        output_json({"peers": peers})
        return

    if not peers:
        print_info("No peer agents registered. Use 'noo agents peer register' or connect via /ws/agent.")
        return

    table = Table(title="Peer Agents", show_lines=True)
    table.add_column("Agent ID", style="bold cyan")
    table.add_column("Name")
    table.add_column("Roles", style="dim")
    table.add_column("Capabilities", style="dim")
    table.add_column("Status")

    for p in peers:
        status = "[green]● connected[/]" if p.get("is_connected") else "[dim]○ offline[/]"
        table.add_row(
            p.get("agent_id", "?"),
            p.get("name", "?"),
            ", ".join(p.get("roles", [])) or "-",
            ", ".join(p.get("capabilities", [])) or "-",
            status,
        )

    console.print(table)
    console.print(
        f"[dim]Total: {data.get('total', 0)} registered  |  "
        f"{data.get('connected', 0)} connected[/dim]"
    )


@peer_app.command("card")
def peer_card(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Show MESH AgentCard (what external harnesses fetch to discover PAI)."""
    run_async(_peer_card_async(gateway))


async def _peer_card_async(gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
            resp = await c.get(f"{gw}/.well-known/agent.json")
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        print_error(f"Failed to fetch AgentCard: {e}")
        return

    if is_json_output():
        output_json(data)
        return

    console.print(f"\n[bold]MESH AgentCard[/bold] — {data.get('description', '')}")
    console.print(f"  Name: [cyan]{data.get('name')}[/cyan]  v{data.get('version', '?')}")
    console.print(f"  Roles: {', '.join(data.get('roles', []))}")

    caps = data.get("capabilities", {})
    if caps:
        console.print("\n[bold]Capabilities:[/bold]")
        for cap, info in caps.items():
            endpoint = info.get("endpoint", "") if isinstance(info, dict) else ""
            console.print(f"  [cyan]{cap}[/cyan]: {endpoint}")

    ep = data.get("endpoints", {})
    if ep:
        console.print("\n[bold]Key endpoints:[/bold]")
        for name, url in ep.items():
            console.print(f"  [dim]{name}[/dim]: {url}")

    auth = data.get("authentication", {})
    console.print(
        f"\n[dim]Auth: {', '.join(auth.get('schemes', []))}  |  "
        f"Register: {auth.get('peer_registration', '?')}  |  "
        f"WS: {ep.get('peer_websocket', '?')}[/dim]"
    )


@peer_app.command("dispatch")
def peer_dispatch(
    agent_id: str = typer.Argument(..., help="Target peer agent ID"),
    task: str = typer.Argument(..., help="Task to dispatch"),
    role: str = typer.Option("agent", "--role", "-r", help="Role label for this task"),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Dispatch a task directly to a connected peer agent."""
    run_async(_peer_dispatch_async(agent_id, task, role, gateway))


async def _peer_dispatch_async(
    agent_id: str, task: str, role: str, gateway: Optional[str]
) -> None:
    import httpx

    gw = gateway or _gw()
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
            resp = await c.post(
                f"{gw}/api/agents/peer/{agent_id}/task",
                json={"task": task, "role": role},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        print_error(f"Dispatch failed: {e}")
        return

    if is_json_output():
        output_json(data)
        return

    print_success(f"Task dispatched to {agent_id}")
    console.print(f"  Task ID: [cyan]{data.get('task_id')}[/cyan]")
    console.print(f"  Result stream: [dim]{data.get('result_subject')}[/dim]")
    print_info("Peer is processing — token stream visible on /ws/collab")
