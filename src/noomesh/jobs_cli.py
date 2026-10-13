# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for job management and scheduler control (noo jobs ...)."""
from __future__ import annotations

import asyncio
import time

from . import json_fast as _json
from typing import Optional

import httpx
import typer
from rich.table import Table

from .cli_utils import (
    cli_auth_headers,
    cli_client_cert,
    cli_http_verify,
    confirm_destructive,
    console,
    get_gateway_url,
    http_fail,
    is_json_output,
    output_json,
    print_error,
    print_info,
    print_success,
    print_warning,
    run_async,
)

jobs_app = typer.Typer(
    help="[bold yellow]Jobs[/] & scheduler management",
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


# ---- Job commands ----

_TERMINAL_STATES = ("completed", "failed", "dead", "cancelled")


async def _poll_job(job_id: str, timeout: int, poll_interval: float = 2.0) -> Optional[dict]:
    """Poll GET /api/jobs/{id} until the job reaches a terminal state.

    Returns the final job record, or None if `timeout` elapsed first.
    Transient gateway HTTP errors are swallowed and polling continues;
    anything else (connection refused, etc.) fails via http_fail.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            job = await _fetch(f"/api/jobs/{job_id}")
        except httpx.HTTPStatusError:
            job = None
        except Exception as e:
            http_fail(e)
        if isinstance(job, dict) and job.get("status") in _TERMINAL_STATES:
            return job
        await asyncio.sleep(poll_interval)
    return None


def _report_terminal_job(job: dict):
    """Print a terminal-state job record; exit 1 unless it completed."""
    status = job.get("status")
    if is_json_output():
        output_json(job)
    elif status == "completed":
        print_success("Job completed")
        result_data = job.get("result", "")
        if result_data:
            console.print(f"\n{result_data}")
    elif status == "cancelled":
        print_warning("Job was cancelled")
    else:
        print_error(f"Job {status}: {job.get('error', 'unknown')}")
    if status != "completed":
        raise typer.Exit(1)


@jobs_app.command("run")
def run_job(
    prompt: str = typer.Argument(..., help="Prompt or task description"),
    async_mode: bool = typer.Option(False, "--async", "-a", help="Return job ID immediately"),
    priority: int = typer.Option(5, "--priority", "-p", help="Priority 0-10 (higher = sooner)"),
    backend: Optional[str] = typer.Option(None, "--backend", "-b", help="Backend to use (vllm, llamacpp, ollama)"),
    node: Optional[str] = typer.Option(None, "--node", "-n", help="Force specific node"),
    timeout: int = typer.Option(300, "--timeout", "-t", help="Timeout in seconds"),
    job_type: str = typer.Option("inference", "--type", help="Job type (inference, tool_exec, model_download)"),
):
    """Submit a job to the scheduler and wait for the result.

    Default: wait for result. Use --async to return the job ID immediately.

    Examples:
        noo jobs run "Hello world" --backend vllm
        noo jobs run "Long task" --async --priority 8
        noo jobs run "Pull images" --type model_download
    """
    run_async(_run_job_async(prompt, async_mode, priority, backend, node, timeout, job_type))


async def _run_job_async(
    prompt: str,
    async_mode: bool,
    priority: int,
    backend: Optional[str],
    node: Optional[str],
    timeout: int,
    job_type: str,
):
    body = {
        "type": job_type,
        "payload": {"prompt": prompt},
        "priority": priority,
        "backend": backend,
        "force_node": node,
        "timeout_sec": timeout,
    }
    try:
        data = await _fetch("/api/jobs/submit", method="POST", json=body)
    except Exception as e:
        http_fail(e)
    job_id = data.get("job_id") if isinstance(data, dict) else None
    if not job_id:
        print_error(f"Gateway returned no job_id: {data}")
        raise typer.Exit(1)

    if async_mode:
        if is_json_output():
            output_json({"job_id": job_id})
        else:
            print_success(f"Job submitted: {job_id}")
        return

    if not is_json_output():
        console.print(f"[dim]Job {job_id} submitted, waiting for result...[/dim]")
    job = await _poll_job(job_id, timeout)
    if job is None:
        print_error(f"Timed out after {timeout}s waiting for job {job_id}")
        print_info(f"Job is still running. Check with: noo jobs status {job_id}")
        raise typer.Exit(1)
    _report_terminal_job(job)


@jobs_app.command("list")
def list_jobs(
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status"),
    node: Optional[str] = typer.Option(None, "--node", help="Filter by node ID"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max jobs to show"),
):
    """List jobs in the scheduler queue."""
    run_async(_list_jobs_async(status, node, limit))


async def _list_jobs_async(status: Optional[str], node: Optional[str], limit: int):
    params = {"limit": limit}
    if status:
        params["status"] = status
    if node:
        params["node"] = node
    try:
        data = await _fetch("/api/jobs", params=params)
    except Exception as e:
        http_fail(e)
    jobs = data if isinstance(data, list) else data.get("jobs", [])
    if is_json_output():
        output_json(data)
        return
    if not jobs:
        print_info("No jobs found.")
        return
    t = Table(title="Jobs", show_lines=False)
    t.add_column("ID", style="cyan")
    t.add_column("Type")
    t.add_column("Status", style="yellow")
    t.add_column("Priority", justify="right")
    t.add_column("Node")
    t.add_column("Created")
    for j in jobs[:limit]:
        t.add_row(
            str(j.get("job_id", j.get("id", "?")))[:12],
            j.get("type", "?"),
            j.get("status", j.get("state", "?")),
            str(j.get("priority", "")),
            j.get("node_id", j.get("node", "-"))[:12] if j.get("node_id") or j.get("node") else "-",
            str(j.get("created_at", "?"))[:19],
        )
    console.print(t)


@jobs_app.command("status")
def job_status(
    job_id: str = typer.Argument(..., help="Job ID"),
    wait: bool = typer.Option(False, "--wait", "-w", help="Poll until the job reaches a terminal state"),
    timeout: int = typer.Option(300, "--timeout", help="Max seconds to wait (with --wait)"),
):
    """Show detailed status for a single job."""
    run_async(_job_status_async(job_id, wait, timeout))


async def _job_status_async(job_id: str, wait: bool = False, timeout: int = 300):
    if wait:
        if not is_json_output():
            console.print(f"[dim]Waiting for job {job_id} to finish...[/dim]")
        data = await _poll_job(job_id, timeout)
        if data is None:
            print_error(f"Timed out after {timeout}s waiting for job {job_id}")
            print_info(f"Job is still running. Check with: noo jobs status {job_id}")
            raise typer.Exit(1)
    else:
        try:
            data = await _fetch(f"/api/jobs/{job_id}")
        except Exception as e:
            http_fail(e)
    if is_json_output():
        output_json(data)
    else:
        console.print_json(data=data)


@jobs_app.command()
def submit(
    type: str = typer.Option("inference", "--type", "-t", help="Job type"),
    priority: int = typer.Option(5, "--priority", "-p", help="Priority 1-10"),
    backend: Optional[str] = typer.Option(None, "--backend", "-b", help="Required backend"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout seconds"),
    payload: Optional[str] = typer.Option(None, "--payload", help="JSON payload string"),
):
    """Submit a new job to the scheduler."""
    parsed_payload = {}
    if payload:
        try:
            parsed_payload = _json.loads(payload)
        except _json.JSONDecodeError:
            print_error("Invalid JSON in --payload")
            raise typer.Exit(1)
    run_async(_submit_async(type, priority, backend, timeout, parsed_payload))


async def _submit_async(
    type: str, priority: int, backend: Optional[str], timeout: int, payload: dict
):
    body = {"type": type, "priority": priority, "timeout_sec": timeout}
    if backend:
        body["backend"] = backend
    if payload:
        body["payload"] = payload
    try:
        data = await _fetch("/api/jobs/submit", method="POST", json=body)
    except Exception as e:
        http_fail(e)
    job_id = data.get("job_id", "?") if isinstance(data, dict) else "?"
    print_success(f"Job submitted: {job_id}")


@jobs_app.command()
def history(limit: int = typer.Option(20, "--limit", "-n", help="Max entries")):
    """Show completed/failed job history."""
    run_async(_history_async(limit))


async def _history_async(limit: int):
    try:
        data = await _fetch("/api/jobs/history", params={"limit": limit})
    except Exception as e:
        http_fail(e)
    jobs = data if isinstance(data, list) else data.get("jobs", [])
    if is_json_output():
        output_json(data)
        return
    if not jobs:
        print_info("No job history.")
        return
    t = Table(title="Job History", show_lines=False)
    t.add_column("ID", style="cyan")
    t.add_column("Type")
    t.add_column("Status")
    t.add_column("Duration")
    for j in jobs[:limit]:
        status = j.get("status", j.get("state", "?"))
        color = "green" if status == "completed" else "red" if status == "failed" else "yellow"
        dur = j.get("duration_ms", j.get("elapsed_ms"))
        dur_str = f"{dur}ms" if dur else "-"
        t.add_row(
            str(j.get("job_id", j.get("id", "?")))[:12],
            j.get("type", "?"),
            f"[{color}]{status}[/{color}]",
            dur_str,
        )
    console.print(t)


@jobs_app.command()
def cancel(job_id: str = typer.Argument(..., help="Job ID to cancel")):
    """Cancel a queued or running job."""
    confirm_destructive("Cancel job", job_id)
    run_async(_cancel_async(job_id))


async def _cancel_async(job_id: str):
    try:
        data = await _fetch(f"/api/jobs/{job_id}", method="DELETE")
    except Exception as e:
        http_fail(e)
    msg = data.get("message", f"Cancelled {job_id}") if isinstance(data, dict) else str(data)
    print_success(msg)


@jobs_app.command()
def reprioritize(
    job_id: str = typer.Argument(..., help="Job ID"),
    priority: int = typer.Argument(..., help="New priority (1-10)"),
):
    """Change priority of a queued job."""
    run_async(_reprioritize_async(job_id, priority))


async def _reprioritize_async(job_id: str, priority: int):
    try:
        await _fetch(
            f"/api/jobs/{job_id}/reprioritize", method="POST", json={"priority": priority}
        )
    except Exception as e:
        http_fail(e)
    print_success(f"Job {job_id} reprioritized to {priority}")


# ---- Scheduler commands ----


@jobs_app.command()
def scheduler():
    """Show scheduler status."""
    run_async(_scheduler_async())


async def _scheduler_async():
    try:
        data = await _fetch("/api/scheduler/status")
    except Exception as e:
        http_fail(e)
    if is_json_output():
        output_json(data)
    else:
        console.print_json(data=data)


@jobs_app.command()
def pause():
    """Pause the job scheduler."""
    run_async(_pause_resume("pause"))


@jobs_app.command()
def resume():
    """Resume the job scheduler."""
    run_async(_pause_resume("resume"))


async def _pause_resume(action: str):
    try:
        data = await _fetch(f"/api/scheduler/{action}", method="POST")
    except Exception as e:
        http_fail(e)
    msg = data.get("message", f"Scheduler {action}d") if isinstance(data, dict) else str(data)
    print_success(msg)


@jobs_app.command()
def drain(node_id: str = typer.Argument(..., help="Node ID to drain")):
    """Drain a node — finish running jobs, accept no new ones."""
    run_async(_drain_undrain("drain", node_id))


@jobs_app.command()
def undrain(node_id: str = typer.Argument(..., help="Node ID to undrain")):
    """Undrain a node — accept new jobs again."""
    run_async(_drain_undrain("undrain", node_id))


async def _drain_undrain(action: str, node_id: str):
    try:
        data = await _fetch(f"/api/scheduler/{action}/{node_id}", method="POST")
    except Exception as e:
        http_fail(e)
    msg = data.get("message", f"Node {node_id} {action}ed") if isinstance(data, dict) else str(data)
    print_success(msg)
