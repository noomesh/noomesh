# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for prompt skills management (noo prompt-skills ...)."""
from __future__ import annotations

from typing import Optional

import httpx
import typer
from rich.table import Table

from .cli_utils import cli_auth_headers, cli_client_cert, cli_http_verify, console, get_gateway_url, is_json_output, output_json, print_error, print_info, print_success, run_async

prompt_skills_app = typer.Typer(
    help="[bold magenta]Prompt skills[/] — expertise templates for the agent",
    rich_markup_mode="rich",
)
_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", **kw):
    async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        fn = {"GET": c.get, "POST": c.post}[method]
        resp = await fn(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@prompt_skills_app.command("list")
def list_skills():
    """List all prompt skills."""
    run_async(_list_async())


async def _list_async():
    try:
        data = await _fetch("/api/prompt-skills")
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    skills = data.get("skills", []) if isinstance(data, dict) else data
    if is_json_output():
        output_json(data)
        return
    if not skills:
        print_info("No prompt skills available.")
        return
    t = Table(title="Prompt Skills", show_lines=False)
    t.add_column("Name", style="cyan")
    t.add_column("Priority", justify="right")
    t.add_column("Fitness", justify="right")
    t.add_column("Core")
    t.add_column("Description")
    for s in skills:
        core = "[green]yes[/green]" if s.get("is_core") else "[dim]no[/dim]"
        t.add_row(
            s.get("name", "?"),
            str(s.get("priority", 5)),
            f"{s.get('fitness', 0.0):.1f}",
            core,
            (s.get("description", "") or "")[:60],
        )
    console.print(t)


@prompt_skills_app.command("info")
def info(name: str = typer.Argument(..., help="Skill name")):
    """Show full details and content of a prompt skill."""
    run_async(_info_async(name))


async def _info_async(name: str):
    try:
        data = await _fetch(f"/api/prompt-skills/{name}")
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    if is_json_output():
        output_json(data)
        return
    if isinstance(data, dict):
        console.print(f"\n[bold cyan]{data.get('name', name)}[/bold cyan]")
        if data.get("description"):
            console.print(f"[dim]{data['description']}[/dim]")
        console.print(f"Tags: {', '.join(data.get('tags', []))}")
        console.print(
            f"Priority: {data.get('priority', 5)} | "
            f"Fitness: {data.get('fitness', 0.0):.1f} | "
            f"Author: {data.get('author', '?')}"
        )
        content = data.get("content", "")
        if content:
            console.print(f"\n{content}")
    else:
        console.print(str(data))


@prompt_skills_app.command("create")
def create(
    name: str = typer.Argument(..., help="Unique skill name (lowercase, hyphens)"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Markdown file with skill content"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="One-line description"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags"),
    priority: int = typer.Option(5, "--priority", "-p", help="Priority 1-10"),
):
    """Create a new prompt skill."""
    content = ""
    if file:
        from pathlib import Path
        p = Path(file)
        if not p.exists():
            print_error(f"File not found: {file}")
            raise typer.Exit(1)
        content = p.read_text()
    else:
        print_info("Enter skill content (Ctrl-D to finish):")
        import sys
        content = sys.stdin.read()
    run_async(_create_async(name, content, description, tags, priority))


async def _create_async(
    name: str,
    content: str,
    description: Optional[str],
    tags: Optional[str],
    priority: int,
):
    body = {"name": name, "content": content, "priority": priority}
    if description:
        body["description"] = description
    if tags:
        body["tags"] = [t.strip() for t in tags.split(",")]
    try:
        data = await _fetch("/api/prompt-skills", method="POST", json=body)
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    if isinstance(data, dict) and data.get("ok"):
        print_success(f"Created skill '{name}'")
    else:
        detail = data.get("detail", str(data)) if isinstance(data, dict) else str(data)
        print_error(detail)


@prompt_skills_app.command("evolve")
def evolve(
    observation: Optional[str] = typer.Option(None, "--observation", "-o", help="Performance observation"),
    role: Optional[str] = typer.Option(None, "--role", help="Agent role (default: coordinator)"),
):
    """Trigger LLM-based skill evolution."""
    run_async(_evolve_async(observation, role))


async def _evolve_async(observation: Optional[str], role: Optional[str]):
    body = {}
    if observation:
        body["observation"] = observation
    if role:
        body["role"] = role
    try:
        data = await _fetch("/api/prompt-skills/evolve", method="POST", json=body)
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    if isinstance(data, dict):
        result = data.get("result", data)
        action = result.get("action", "unknown")
        if action == "none":
            print_info("No skill evolution needed at this time.")
        else:
            print_success(f"Evolution action: {action}")
            console.print_json(data=result)
    else:
        console.print(str(data))
