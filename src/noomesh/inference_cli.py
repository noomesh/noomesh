# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for quick inference (noo inference ...)."""
from __future__ import annotations

from typing import Optional

import httpx
import typer

from .cli_utils import (
    cli_auth_headers,
    cli_client_cert,
    cli_http_verify,
    console,
    get_gateway_url,
    http_fail,
    is_json_output,
    output_json,
    run_async,
)

inference_app = typer.Typer(
    help="[bold]Inference[/] — run prompts on the GPU cluster",
    rich_markup_mode="rich",
)
_gw = get_gateway_url


@inference_app.command("run")
def run_inference(
    prompt: str = typer.Argument(..., help="Prompt text"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name"),
    backend: Optional[str] = typer.Option(None, "--backend", "-b", help="Backend (vllm/ollama/llamacpp)"),
    node: Optional[str] = typer.Option(None, "--node", "-n", help="Pin to a specific node (bypasses model-based routing). Use for liveness verification."),
    max_tokens: int = typer.Option(512, "--max-tokens", help="Max tokens to generate"),
    temperature: float = typer.Option(0.7, "--temperature", "-t", help="Sampling temperature"),
):
    """Run a single inference prompt on the cluster."""
    run_async(_run_async(prompt, model, backend, node, max_tokens, temperature))


async def _run_async(
    prompt: str,
    model: Optional[str],
    backend: Optional[str],
    node: Optional[str],
    max_tokens: int,
    temperature: float,
):
    body = {"prompt": prompt, "max_tokens": max_tokens, "temperature": temperature}
    if model:
        body["model"] = model
    if backend:
        body["backend"] = backend
    if node:
        body["node"] = node
    try:
        async with httpx.AsyncClient(
            timeout=120.0,
            verify=cli_http_verify(),
            cert=cli_client_cert(),
            headers=cli_auth_headers(),
        ) as c:
            with console.status("Running inference..."):
                resp = await c.post(f"{_gw()}/api/inference", json=body)
                resp.raise_for_status()
                data = resp.json()
    except Exception as e:
        http_fail(e)
    if is_json_output():
        output_json(data)
        return
    if isinstance(data, dict):
        # Rust gateway wraps the payload in {"success": ..., "data": {...}};
        # older/direct backends return top-level "response"/"text".
        inner = data.get("data") if isinstance(data.get("data"), dict) else data
        text = inner.get("response", inner.get("text", ""))
    else:
        text = str(data)
    console.print(text)


@inference_app.command("agent")
def agent_run(
    prompt: str = typer.Argument(..., help="Task or question"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model name"),
    max_iters: int = typer.Option(10, "--max-iters", help="Max agent loop iterations"),
    no_tools: bool = typer.Option(False, "--no-tools", help="Disable tool calling"),
):
    """Run the full agentic loop (plan + tools + reflect)."""
    run_async(_agent_async(prompt, model, max_iters, no_tools))


async def _agent_async(
    prompt: str, model: Optional[str], max_iters: int, no_tools: bool
):
    body = {
        "prompt": prompt,
        "max_iterations": max_iters,
        "tools_enabled": not no_tools,
    }
    if model:
        body["model"] = model
    try:
        async with httpx.AsyncClient(
            timeout=120.0,
            verify=cli_http_verify(),
            cert=cli_client_cert(),
            headers=cli_auth_headers(),
        ) as c:
            with console.status("Running agentic loop..."):
                resp = await c.post(f"{_gw()}/api/agent/run", json=body)
                resp.raise_for_status()
                data = resp.json()
    except Exception as e:
        http_fail(e)
    if is_json_output():
        output_json(data)
        return
    if isinstance(data, dict):
        console.print(data.get("response", ""))
        tool_calls = data.get("tool_calls", [])
        if tool_calls:
            console.print(
                f"\n[dim]Agent used {len(tool_calls)} tool(s) over "
                f"{data.get('iterations', 0)} iteration(s)[/dim]"
            )
    else:
        console.print(str(data))
