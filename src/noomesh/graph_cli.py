# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for knowledge graph exploration (noo graph ...)."""
from __future__ import annotations

import httpx
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
    run_async,
)

graph_app = typer.Typer(
    help="[bold green]Knowledge graph[/] exploration",
    rich_markup_mode="rich",
)
_gw = get_gateway_url


async def _fetch(path: str, method: str = "GET", **kw):
    async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        resp = await (c.get if method == "GET" else c.post)(f"{_gw()}{path}", **kw)
        resp.raise_for_status()
        return resp.json()


@graph_app.command()
def search(query: str = typer.Argument(..., help="Entity name or partial name")):
    """Search for entities in the knowledge graph."""
    run_async(_search_async(query))


async def _search_async(query: str):
    try:
        data = await _fetch("/api/v1/graph/entities", params={"q": query})
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    entities = data if isinstance(data, list) else data.get("entities", [])
    if is_json_output():
        output_json(data)
        return
    if not entities:
        print_info("No entities found.")
        return
    t = Table(title=f"Entities matching '{query}'", show_lines=False)
    t.add_column("ID", style="dim")
    t.add_column("Name", style="cyan")
    t.add_column("Type")
    for e in entities:
        t.add_row(
            str(e.get("id", "?"))[:12],
            e.get("name", "?"),
            e.get("entity_type", "?"),
        )
    console.print(t)


@graph_app.command()
def detail(entity_id: str = typer.Argument(..., help="Entity UUID")):
    """Show full details of a graph entity."""
    run_async(_detail_async(entity_id))


async def _detail_async(entity_id: str):
    try:
        data = await _fetch(f"/api/v1/graph/entities/{entity_id}")
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    if is_json_output():
        output_json(data)
    else:
        console.print_json(data=data)


@graph_app.command()
def neighbors(
    entity_id: str = typer.Argument(..., help="Entity UUID"),
    hops: int = typer.Option(1, "--hops", "-H", help="Traversal depth (1-3)", min=1, max=3),
):
    """Find entities connected to a given entity."""
    run_async(_neighbors_async(entity_id, hops))


async def _neighbors_async(entity_id: str, hops: int):
    try:
        data = await _fetch(
            f"/api/v1/graph/entities/{entity_id}/neighbors", params={"hops": hops}
        )
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    neighbors = data if isinstance(data, list) else data.get("neighbors", [])
    if is_json_output():
        output_json(data)
        return
    if not neighbors:
        print_info("No neighbors found.")
        return
    t = Table(title=f"Neighbors (hops={hops})", show_lines=False)
    t.add_column("ID", style="dim")
    t.add_column("Name", style="cyan")
    t.add_column("Type")
    t.add_column("Relation")
    for n in neighbors:
        t.add_row(
            str(n.get("id", "?"))[:12],
            n.get("name", "?"),
            n.get("entity_type", "?"),
            n.get("relation", n.get("relationship", "-")),
        )
    console.print(t)


@graph_app.command()
def stats():
    """Show knowledge graph statistics."""
    run_async(_stats_async())


async def _stats_async():
    try:
        data = await _fetch("/api/v1/graph/stats")
    except Exception as e:
        print_error(f"Failed: {e}")
        return
    if is_json_output():
        output_json(data)
        return
    t = Table(show_header=False, box=None)
    t.add_column("Key", style="dim")
    t.add_column("Value")
    for key in ("total_entities", "total_edges", "entity_types", "documents_with_entities"):
        if key in data:
            val = data[key]
            label = key.replace("_", " ").capitalize()
            if isinstance(val, dict):
                t.add_row(label, ", ".join(f"{k}: {v}" for k, v in val.items()))
            else:
                t.add_row(label, str(val))
    console.print(t)
