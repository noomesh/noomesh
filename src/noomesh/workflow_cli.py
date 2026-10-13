# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for workflow execution.

Provides workflow listing and execution via the gateway API.
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

workflow_app = typer.Typer(
    name="workflow",
    help="[bold yellow]Workflow[/bold yellow] automation",
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


@workflow_app.command("list")
def list_workflows(
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """List available workflows."""
    run_async(_list_async(gateway))


async def _list_async(gateway: Optional[str]) -> None:
    import httpx

    gw = gateway or _gw()

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as c:
            resp = await c.get(f"{gw}/api/workflows")
            resp.raise_for_status()
            workflows = resp.json()
    except httpx.ConnectError:
        print_info("Gateway unavailable, showing built-in workflows:")
        _show_local_workflows()
        return
    except Exception as e:
        print_error(f"Failed to fetch workflows: {e}")
        _show_local_workflows()
        return

    if is_json_output():
        output_json(workflows)
        return

    table = Table(title="Available Workflows", show_lines=True)
    table.add_column("Name", style="bold yellow")
    table.add_column("Description")
    table.add_column("Steps", justify="right")

    for wf in workflows:
        table.add_row(
            wf["name"],
            wf.get("description", ""),
            str(wf.get("step_count", "-")),
        )

    console.print(table)


def _show_local_workflows() -> None:
    """Show workflows from the local module."""
    from .workflows import (
        CODE_DEVELOPMENT_WORKFLOW,
        DATA_ANALYSIS_WORKFLOW,
        RESEARCH_WORKFLOW,
    )

    workflows = [RESEARCH_WORKFLOW, CODE_DEVELOPMENT_WORKFLOW, DATA_ANALYSIS_WORKFLOW]

    table = Table(title="Available Workflows (local)", show_lines=True)
    table.add_column("Name", style="bold yellow")
    table.add_column("Description")
    table.add_column("Steps", justify="right")

    for wf in workflows:
        table.add_row(wf.name, wf.description, str(len(wf.steps)))

    console.print(table)


@workflow_app.command("run")
def run_workflow(
    name: str = typer.Argument(..., help="Workflow name (deep_research, code_development, data_analysis)"),
    input_var: Optional[list[str]] = typer.Option(
        None, "--input", "-i",
        help="Input variable as key=value (repeatable)",
    ),
    gateway: Optional[str] = typer.Option(None, "--gateway", "-G", help="Gateway URL"),
) -> None:
    """Execute a named workflow with optional inputs.

    Examples:

        noo workflow run deep_research -i topic="quantum computing"

        noo workflow run code_development -i task="build a REST API"
    """
    run_async(_run_workflow_async(name, input_var, gateway))


async def _run_workflow_async(
    name: str,
    input_var: Optional[list[str]],
    gateway: Optional[str],
) -> None:
    import httpx

    gw = gateway or _gw()

    # Parse input variables
    inputs: dict = {}
    if input_var:
        for item in input_var:
            if "=" not in item:
                print_error(f"Invalid input format: {item!r} (expected key=value)")
                return
            key, _, value = item.partition("=")
            inputs[key.strip()] = value.strip()

    payload = {"workflow_name": name, "inputs": inputs}

    with console.status(f"Running workflow [bold]{name}[/bold]..."):
        try:
            async with httpx.AsyncClient(timeout=600.0, verify=cli_http_verify(), cert=cli_client_cert(), headers=cli_auth_headers()) as client:
                response = await client.post(
                    f"{gw}/api/workflows/run",
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
    status = data.get("status", "unknown")
    style = "green" if status == "completed" else "red"
    console.print(f"\nWorkflow [bold]{name}[/bold]: [{style}]{status}[/{style}]")
    console.print(f"Duration: {data.get('total_duration_ms', 0):.0f}ms")

    steps = data.get("steps", [])
    if steps:
        console.print()
        for step in steps:
            step_status = step.get("status", "unknown")
            icon = {"completed": "[green]OK[/green]", "failed": "[red]FAIL[/red]", "skipped": "[dim]SKIP[/dim]"}.get(
                step_status, step_status
            )
            console.print(f"  {icon}  {step['step_name']} ({step.get('duration_ms', 0):.0f}ms)")
            if step.get("output"):
                output = step["output"]
                if len(output) > 500:
                    output = output[:500] + "..."
                console.print(f"       {output}")
            if step.get("error"):
                print_error(f"       {step['error']}")

    if status == "completed":
        print_success("Workflow complete")
    else:
        print_error(f"Workflow finished with status: {status}")
