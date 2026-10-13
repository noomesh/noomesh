# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for skill management — ``noo skills list/info/run``."""
from __future__ import annotations

from . import json_fast as json
from typing import Optional

import typer

from .cli_utils import (
    console,
    get_gateway_url,
    print_error,
    print_info,
    print_success,
    run_async,
)

skills_app = typer.Typer(
    help="Manage and run containerized skills",
    rich_markup_mode="rich",
)


@skills_app.command("list")
def list_skills() -> None:
    """List all available skills."""
    from rich.table import Table

    from .skills import get_skill_registry

    registry = get_skill_registry()
    skills = registry.list_skills()

    if not skills:
        print_info("No skills found.")
        print_info(
            f"Place skill directories in {registry.builtin_dir} "
            f"or {registry.user_dir}"
        )
        return

    table = Table(title="Available Skills")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Author", style="dim")
    table.add_column("GPU", justify="center")
    table.add_column("Image")
    table.add_column("Description")

    for s in skills:
        table.add_row(
            s.name,
            s.version,
            s.author,
            "[green]yes[/]" if s.container.gpu else "[dim]no[/]",
            s.container.image,
            s.description[:60],
        )

    console.print(table)


@skills_app.command("info")
def skill_info(
    name: str = typer.Argument(..., help="Skill name"),
) -> None:
    """Show detailed information about a skill."""
    from .skills import get_skill_registry

    registry = get_skill_registry()
    manifest = registry.get(name)

    if not manifest:
        print_error(f"Skill not found: {name}")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]{manifest.name}[/] v{manifest.version}")
    console.print(f"  Author: {manifest.author}")
    console.print(f"  Description: {manifest.description}")
    console.print(f"  Directory: {manifest.skill_dir}")

    console.print("\n[bold]Container:[/]")
    console.print(f"  Image: {manifest.container.image}")
    console.print(f"  Command: {' '.join(manifest.container.command)}")
    console.print(f"  Timeout: {manifest.container.timeout}s")
    console.print(f"  Memory: {manifest.container.memory_limit}")
    console.print(f"  Network: {manifest.container.network}")
    console.print(f"  GPU: {manifest.container.gpu}")

    console.print("\n[bold]Permissions:[/]")
    console.print(f"  Filesystem: {manifest.permissions.filesystem}")
    console.print(f"  Network: {manifest.permissions.network}")
    console.print(f"  Shell: {manifest.permissions.shell}")

    if manifest.inputs:
        console.print("\n[bold]Inputs:[/]")
        for p in manifest.inputs:
            req = " [red](required)[/]" if p.required else " [dim](optional)[/]"
            console.print(f"  {p.name}: {p.type}{req}")
            if p.description:
                console.print(f"    {p.description}")

    if manifest.outputs:
        console.print("\n[bold]Outputs:[/]")
        for p in manifest.outputs:
            console.print(f"  {p.name}: {p.type}")
            if p.description:
                console.print(f"    {p.description}")

    console.print()


@skills_app.command("run")
def run_skill(
    name: str = typer.Argument(..., help="Skill name"),
    input_json: str = typer.Argument(..., help="JSON string of inputs"),
    node: Optional[str] = typer.Option(None, "--node", "-n", help="Target node ID"),
    via_gateway: bool = typer.Option(
        False, "--gateway", "-g", help="Run via gateway API instead of local executor"
    ),
) -> None:
    """Run a skill with JSON inputs."""
    try:
        inputs = json.loads(input_json)
    except json.JSONDecodeError as exc:
        print_error(f"Invalid JSON input: {exc}")
        raise typer.Exit(1)

    if via_gateway:
        _run_via_gateway(name, inputs, node)
    else:
        run_async(_run_local(name, inputs, node))


async def _run_local(name: str, inputs: dict, node_id: Optional[str]) -> None:
    """Run a skill using the local executor."""
    from .skills import get_skill_executor, get_skill_registry

    registry = get_skill_registry()
    manifest = registry.get(name)
    if not manifest:
        print_error(f"Skill not found: {name}")
        return

    executor = get_skill_executor()

    with console.status(f"Running skill [cyan]{name}[/]..."):
        result = await executor.execute_skill(
            manifest=manifest,
            inputs=inputs,
            node_id=node_id,
        )

    if result.success:
        print_success(f"Skill completed in {result.duration_ms:.0f}ms")
        console.print_json(json.dumps(result.output, default=str))
    else:
        print_error(f"Skill failed: {result.error}")


def _run_via_gateway(name: str, inputs: dict, node_id: Optional[str]) -> None:
    """Run a skill via the gateway API."""
    import httpx

    gateway_url = get_gateway_url()
    payload = {"inputs": inputs}
    if node_id:
        payload["node_id"] = node_id

    with console.status(f"Running skill [cyan]{name}[/] via gateway..."):
        try:
            resp = httpx.post(
                f"{gateway_url}/api/skills/{name}/run",
                json=payload,
                timeout=120.0,
            )
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

    if data.get("success"):
        print_success(f"Skill completed in {data.get('duration_ms', 0):.0f}ms")
        console.print_json(json.dumps(data.get("output", {}), default=str))
    else:
        print_error(f"Skill failed: {data.get('error', 'unknown')}")
