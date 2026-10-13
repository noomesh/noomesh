# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Interactive chat CLI — gateway-aware with direct Ollama fallback."""
from __future__ import annotations

import asyncio
from . import json_fast as json
from pathlib import Path
from typing import Optional

import typer

from .cli_utils import (
    cli_client_cert,
    cli_http_verify,
    console,
    get_gateway_url,
    print_error,
    print_hint,
    run_async,
)
from .config import load_config

# NOTE: .factory (→ agent → memory → torch, ~2s) and .llm.ollama are imported
# inside the functions that need them so mounting `noo chat` stays cheap.

chat_app = typer.Typer(add_completion=False, rich_markup_mode="rich")


@chat_app.callback(invoke_without_command=True)
def chat(
    config: Optional[Path] = typer.Option(None, help="Path to config YAML."),
    model: Optional[str] = typer.Option(None, help="Override model."),
    base_url: Optional[str] = typer.Option(None, help="Override Ollama base URL."),
    tool_mode: Optional[str] = typer.Option(None, help="Tool mode: [cyan]auto[/] or [cyan]off[/]."),
    use_cluster: bool = typer.Option(True, help="Use cluster gateway if available."),
) -> None:
    """💬 [bold]Interactive chat[/] with the cluster."""
    import httpx

    # Check if cluster gateway is available
    gateway_url = get_gateway_url()
    cluster_available = False

    if use_cluster:
        with console.status("Checking cluster..."):
            try:
                response = httpx.get(f"{gateway_url}/health", timeout=2.0)
                if response.status_code == 200:
                    cluster_available = True
                    from .cli_utils import print_info
                    print_info(f"Using cluster gateway at {gateway_url}")
            except Exception:
                pass

    if cluster_available:
        # Use cluster-aware chat
        _cluster_chat(gateway_url, model)
    else:
        # Fall back to direct connection
        overrides = {}
        if model or base_url:
            overrides["ollama"] = {}
            if model:
                overrides["ollama"]["model"] = model
            if base_url:
                overrides["ollama"]["base_url"] = base_url
        if tool_mode:
            overrides["agent"] = {"tool_mode": tool_mode}

        with console.status("Loading agent..."):
            from .factory import build_agent

            config_obj, _ = load_config(config, overrides)
            agent = build_agent(config_obj)

        _interactive_chat(agent)


def _interactive_chat(agent) -> None:
    """Interactive chat loop with Rich spinners and streaming output."""
    import httpx

    from .llm.ollama import OllamaError

    session = agent.new_session()
    print_hint("Type /exit or /quit to end the conversation.\n")

    while True:
        try:
            user_input = input("you> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input:
            continue

        if user_input.lower() in {"/exit", "/quit", "quit", "exit"}:
            break

        status = console.status("Thinking...")
        status.start()
        first_token = True

        try:
            console.print("noo> ", end="")
            for event in agent.stream(session, user_input):
                if event["type"] == "token":
                    if first_token:
                        status.stop()
                        first_token = False
                    console.print(event["content"], end="", highlight=False)
                elif event["type"] == "tool_start":
                    status.update(f"Running {event['name']}...")
                elif event["type"] == "tool_complete":
                    status.update("Thinking...")
                elif event["type"] == "tool_error":
                    status.update("Thinking...")
                elif event["type"] == "error":
                    if first_token:
                        status.stop()
                        first_token = False
                    console.print(event["message"], end="", highlight=False)

            # If we never got a token, stop the spinner
            if first_token:
                status.stop()

            console.print()  # newline after response

        except KeyboardInterrupt:
            console.print("\n[dim](interrupted)[/dim]")
        except OllamaError as exc:
            print_error(str(exc))
        except httpx.HTTPError as exc:
            print_error(f"LLM request failed: {exc}")
        except Exception as exc:
            print_error(str(exc))
        finally:
            status.stop()


def _cluster_chat(gateway_url: str, model: Optional[str] = None) -> None:
    """Sync entry point — delegates to async."""
    run_async(_cluster_chat_async(gateway_url, model))


async def _cluster_chat_async(gateway_url: str, model: Optional[str] = None) -> None:
    """Chat using cluster gateway with async streaming."""
    import httpx

    print_hint("Type /exit or /quit to end the conversation.\n")

    async with httpx.AsyncClient(timeout=120.0, verify=cli_http_verify(), cert=cli_client_cert()) as client:
        while True:
            try:
                user_input = await asyncio.to_thread(input, "you> ")
                user_input = user_input.strip()
            except (KeyboardInterrupt, EOFError):
                break

            if not user_input:
                continue

            if user_input.lower() in {"/exit", "/quit", "quit", "exit"}:
                break

            status = console.status("Thinking...")
            status.start()
            first_token = True
            backend_info = ""

            try:
                console.print("noo> ", end="")
                async with client.stream(
                    "POST",
                    f"{gateway_url}/api/inference/stream",
                    json={"prompt": user_input, "model": model},
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if event["type"] == "content":
                            if first_token:
                                status.stop()
                                first_token = False
                            console.print(event["text"], end="", highlight=False)
                        elif event["type"] == "metadata":
                            backend_info = f"[{event['backend']} on {event['node_id']}]"
                        elif event["type"] == "error":
                            if first_token:
                                status.stop()
                                first_token = False
                            print_error(event.get("message", "unknown error"))
                        elif event["type"] == "done":
                            pass  # stream finished

                if first_token:
                    status.stop()

                console.print()  # newline after response
                if backend_info:
                    print_hint(f"{backend_info}\n")

            except KeyboardInterrupt:
                console.print("\n[dim](interrupted)[/dim]")
            except httpx.HTTPStatusError as e:
                if first_token:
                    status.stop()
                try:
                    error_detail = e.response.json().get("detail", str(e))
                except Exception:
                    error_detail = str(e)
                print_error(error_detail)
            except Exception as e:
                if first_token:
                    status.stop()
                print_error(str(e))
            finally:
                status.stop()
