# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for cluster tool management."""

from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.table import Table

from ..cli_utils import (
    cli_httpx_kwargs,
    console,
    get_gateway_url,
    is_json_output,
    output_json,
    print_error,
    print_hint,
    print_warning,
)

tools_app = typer.Typer(help="🔧 Manage [bold]cluster tools[/]", rich_markup_mode="rich")


@tools_app.command("list")
def list_tools(
    node_id: Optional[str] = typer.Option(None, "--node", help="Filter by node ID"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed info"),
) -> None:
    """List all available tools in the cluster."""
    gateway_url = get_gateway_url()

    try:
        with console.status("Fetching tools..."):
            if node_id:
                # Get tools for specific node
                response = httpx.get(
                    f"{gateway_url}/api/tools/nodes/{node_id}",
                    timeout=5.0, **cli_httpx_kwargs()
                )
            else:
                # Get all cluster tools
                response = httpx.get(
                    f"{gateway_url}/tools/list",
                    timeout=5.0, **cli_httpx_kwargs()
                )

            response.raise_for_status()
            data = response.json()

        if is_json_output():
            output_json(data)
            return

        if node_id:
            # Node-specific tools
            tools = data.get("tools", [])
            console.print(f"\n[bold cyan]Tools on node {node_id}:[/bold cyan]")
            print_hint(f"Total: {len(tools)} tools\n")

            if not tools:
                print_warning("No tools available on this node.")
                return

            for tool in tools:
                console.print(f"[green]•[/green] [bold]{tool['name']}[/bold]")
                if verbose:
                    print_hint(f"  {tool.get('description', 'No description')}")

        else:
            # All cluster tools
            tools = data.get("tools", [])
            stats = data.get("stats", {})

            # Stats summary
            console.print("\n[bold cyan]Cluster Tools Overview[/bold cyan]")
            print_hint(f"Total: {stats.get('total_tools', len(tools))} | "
                       f"Base: {stats.get('base_tools', 0)} | "
                       f"Specialized: {stats.get('node_specific_tools', 0)}\n")

            if not tools:
                print_warning("No tools available in cluster.")
                return

            # Create table
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Tool", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Availability", style="yellow")
            if verbose:
                table.add_column("Description", style="dim")

            for tool in tools:
                tool_type = "Base" if tool.get('is_base_tool') else "Specialized"
                nodes = tool.get('available_on_nodes', [])
                availability = "All nodes" if tool.get('is_base_tool') else f"{len(nodes)} node(s)"

                if verbose:
                    table.add_row(
                        tool['name'],
                        tool_type,
                        availability,
                        tool.get('description', 'No description')[:50]
                    )
                else:
                    table.add_row(tool['name'], tool_type, availability)

            console.print(table)

            # Show node list for specialized tools if verbose
            if verbose:
                console.print("\n[bold]Specialized Tool Locations:[/bold]")
                for tool in tools:
                    if not tool.get('is_base_tool'):
                        nodes = tool.get('available_on_nodes', [])
                        console.print(f"  [green]{tool['name']}[/green]: {', '.join(nodes)}")

    except httpx.HTTPStatusError as e:
        print_error(f"HTTP error: {e.response.status_code}")
        if e.response.status_code == 501:
            print_warning("Cluster features not available. Is the gateway running?")
    except httpx.RequestError as e:
        print_error(f"Connection error: {e}")
        print_warning(f"Cannot connect to gateway at {gateway_url}")
        print_hint("Set CONTROLLER_URL environment variable or check gateway status")
    except Exception as e:
        print_error(str(e))


@tools_app.command("select")
def select_tools(
    prompt: str = typer.Argument(..., help="Prompt to select tools for"),
) -> None:
    """Preview which tools would be selected for a prompt."""
    gateway_url = get_gateway_url()

    try:
        with console.status("Selecting tools..."):
            response = httpx.post(
                f"{gateway_url}/tools/select",
                json={"prompt": prompt},
                timeout=5.0, **cli_httpx_kwargs()
            )
            response.raise_for_status()
            data = response.json()

        tools = data.get("tools", [])

        if is_json_output():
            output_json(data)
            return

        if not tools:
            print_warning("No tools selected for this prompt.")
            print_hint("This prompt may not require any specialized tools.")
            return

        console.print(f"\n[bold cyan]Selected {len(tools)} tool(s) for prompt:[/bold cyan]")
        print_hint(f"\"{prompt}\"\n")

        for i, tool in enumerate(tools, 1):
            console.print(f"{i}. [green]{tool['name']}[/green]")
            print_hint(f"   {tool.get('description', 'No description')}")

    except httpx.HTTPStatusError as e:
        print_error(f"HTTP error: {e.response.status_code}")
    except httpx.RequestError as e:
        print_error(f"Connection error: {e}")
        print_warning(f"Cannot connect to gateway at {gateway_url}")
    except Exception as e:
        print_error(str(e))


@tools_app.command("info")
def tool_info(
    tool_name: str = typer.Argument(..., help="Name of the tool to get info about"),
) -> None:
    """Get detailed information about a specific tool."""
    gateway_url = get_gateway_url()

    try:
        with console.status("Fetching tool info..."):
            response = httpx.get(
                f"{gateway_url}/tools/list",
                timeout=5.0, **cli_httpx_kwargs()
            )
            response.raise_for_status()
            data = response.json()

        tools = data.get("tools", [])
        tool = next((t for t in tools if t['name'] == tool_name), None)

        if tool and is_json_output():
            output_json(tool)
            return

        if not tool:
            print_error(f"Tool '{tool_name}' not found.")
            print_hint("\nAvailable tools:")
            for t in tools[:5]:
                console.print(f"  • {t['name']}")
            if len(tools) > 5:
                console.print(f"  ... and {len(tools) - 5} more")
            return

        console.print(f"\n[bold cyan]Tool: {tool['name']}[/bold cyan]")
        console.print(f"[dim]{'─' * 50}[/dim]")

        console.print(f"\n[bold]Type:[/bold] {'Base Tool (all nodes)' if tool.get('is_base_tool') else 'Specialized Tool'}")

        console.print("\n[bold]Description:[/bold]")
        console.print(f"{tool.get('description', 'No description available')}")

        console.print("\n[bold]Availability:[/bold]")
        if tool.get('is_base_tool'):
            console.print("  [green]\u2713[/green] Available on all cluster nodes")
        else:
            nodes = tool.get('available_on_nodes', [])
            if nodes:
                console.print(f"  Available on {len(nodes)} node(s): {', '.join(nodes)}")
            else:
                print_warning("  Not currently available on any node")

        console.print("\n[bold]Parameters:[/bold]")
        params = tool.get('parameters', {})
        if params:
            properties = params.get('properties', {})
            required = params.get('required', [])

            if properties:
                for param_name, param_spec in properties.items():
                    req_marker = "[red]*[/red]" if param_name in required else " "
                    param_type = param_spec.get('type', 'any')
                    param_desc = param_spec.get('description', 'No description')
                    console.print(f"  {req_marker} {param_name} ({param_type}): {param_desc}")
            else:
                print_hint("  No parameters defined")
        else:
            print_hint("  No parameters")

    except httpx.HTTPStatusError as e:
        print_error(f"HTTP error: {e.response.status_code}")
    except httpx.RequestError as e:
        print_error(f"Connection error: {e}")
        print_warning(f"Cannot connect to gateway at {gateway_url}")
    except Exception as e:
        print_error(str(e))


@tools_app.command("export")
def export_tools(
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Destination file (default: the discovered config/tools.json)",
    ),
    check: bool = typer.Option(
        False, "--check",
        help="Don't write; exit 1 if the file's content differs from the registry",
    ),
) -> None:
    """Render the @tool registry to config/tools.json (deterministic output).

    The @tool declarations in noomesh/tools/defs/ are authoritative;
    config/tools.json is a generated artifact consumed by the Rust
    coordinator. Run this after adding or changing a tool declaration.
    """
    from ..tools.decl import (
        default_tools_json_path,
        render_tools_json,
        tools_json_matches,
    )

    target = output or default_tools_json_path()

    try:
        if check:
            if not target.exists():
                print_error(f"{target} does not exist")
                raise typer.Exit(1)
            if tools_json_matches(target):
                console.print(f"[green]OK[/green] {target} matches the tool registry")
                return
            print_error(f"{target} is out of date with the @tool registry")
            print_hint("Run `noo tools export` to regenerate it.")
            raise typer.Exit(1)

        rendered = render_tools_json()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {target}")
        print_hint("Restart the Rust gateway to pick up schema changes.")
    except typer.Exit:
        raise
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)


if __name__ == "__main__":
    tools_app()
