# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster management CLI - usable by both humans and agents!

The agent can programmatically call these commands to manage the cluster.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

import typer
import httpx
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
import structlog

from ..cli_utils import (
    cli_httpx_kwargs,
    console,
    confirm_destructive,
    fatal,
    get_gateway_url,
    is_json_output,
    output_json,
    print_error,
    print_info,
    print_success,
    print_warning,
)


logger = structlog.get_logger()
cluster_app = typer.Typer(
    name="cluster",
    help="🖥️  [bold]Cluster[/] management",
    rich_markup_mode="rich",
)


# ── Shared helpers ──────────────────────────────────────────────────




def _get_online_nodes() -> list[dict]:
    """Get all online nodes from gateway."""
    gateway_url = get_gateway_url()
    try:
        response = httpx.get(f"{gateway_url}/api/cluster/nodes", timeout=10.0, **cli_httpx_kwargs())
        response.raise_for_status()
    except Exception as e:
        fatal(f"Failed to reach gateway: {e}")

    return [n for n in response.json().get("nodes", []) if n.get("status") == "online"]




def _get_inventory_hosts() -> dict[str, str]:
    """Read SSH hosts (IPs) from the retired ansible inventory.

    ALWAYS EMPTY since 3695e129: the ansible inventory tree was deleted.

    Returns dict of node_id -> ansible_host (IP).
    """
    hosts_file = Path(__file__).resolve().parents[3] / "ansible" / "inventory" / "hosts"
    hosts = {}
    if not hosts_file.exists():
        return hosts
    for line in hosts_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("#"):
            continue
        parts = line.split()
        node_id = parts[0]
        for p in parts[1:]:
            if p.startswith("ansible_host="):
                hosts[node_id] = p.split("=", 1)[1]
    return hosts


# ── Tab completion (shell completion via `noo --install-completion`) ──
# Callbacks must be fast and never raise: they run on every <TAB>.
# Nodes come from the ansible inventory file (offline, instant); models
# from the controller store glob. No network calls.

# Backends the node-agent can provision — derived from the BackendProfile
# registry (noomesh.backends), the single Python-side backend table.
from ..backends import provisionable_backends as _provisionable_backends
_KNOWN_BACKENDS = _provisionable_backends()

# The data root used when NOO_DATA_ROOT is unset: neutral, not one machine's
# Held to the node agent's and the noo CLI's value by
# tests/test_data_root_default_parity.py.
DEFAULT_DATA_ROOT = "/var/lib/noo"


def _controller_store() -> Path:
    """Resolve the controller model store: $MODELS_DIR, else
    $NOO_DATA_ROOT/models (.env fallback; default DEFAULT_DATA_ROOT/models)."""
    project_root = Path(__file__).resolve().parents[3]
    env_vals: dict[str, str] = {}
    env_file = project_root / ".env"
    if env_file.exists():
        try:
            for line in env_file.read_text().splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, _, v = line.partition("=")
                    env_vals[k.strip()] = v.strip()
        except Exception:
            pass
    return Path(
        os.environ.get("MODELS_DIR") or env_vals.get("MODELS_DIR")
        or str(Path(os.environ.get("NOO_DATA_ROOT")
                    or env_vals.get("NOO_DATA_ROOT", DEFAULT_DATA_ROOT)) / "models")
    )


def _complete_node_ids(incomplete: str):
    try:
        ids = sorted(_get_inventory_hosts().keys())
    except Exception:
        return []
    return [i for i in ids if i.startswith(incomplete)]


def _complete_model_files(incomplete: str):
    try:
        return sorted(
            f.name for f in _controller_store().glob("*.gguf")
            if f.name.startswith(incomplete)
        )
    except Exception:
        return []


def _complete_backends(incomplete: str):
    return [b for b in _KNOWN_BACKENDS if b.startswith(incomplete)]


# ─────────────────────────────────────────────────────────────────────────
# REMOVED 2026-09-11 — every `noo-py cluster` verb that reached a node over
# SSH (security tracker.
#
# Deleted here: _ssh_pai and _resolve_ssh_user, plus ship-model, clean-node,
# exec, logs, set-primary, reconnect, clean, sync-models, sync-model-files,
# sync-images, upgrade-agents and their ssh/scp helpers (_ship_compose_file,
# _ship_cluster_env, _sync_image_save_load, _sync_node_agent_arm,
# _pipe_save_to_ssh, _restart_backends_for_image_change).
#
# Three independent reasons, any one of which is sufficient:
#
#  1. The transport is gone. The controller→node SSH lane was removed with
#     the cluster-executor; no controller holds a key and node sshd is down.
#     These verbs fail with ssh 255 — or worse, `sync-models` counted a
#     non-zero remote exit as a success ("partial success still counts").
#  2. They assume a repo checkout and a venv at a fixed path on the node,
#     which enrolment stopped creating when the agent became a host process.
#  3. Every one of them has a living Rust twin on a rail: `exec`/`logs` on
#     the dispatch rail, `sync-model-files`/`sync-images`/`upgrade-agents`
#     on the artifact rail, `clean`/`teardown-node`/`forget` through the
#     node-agent, `set-primary` as a control-plane rename with the Postgres
#     promotion run ON the target.
#
# `noo cluster <verb>` reaches the Rust front door first and only falls
# through to this module for verbs it does not own, so deleting these makes
# the Rust implementation the single one — it does not orphan a verb.
# tests/test_no_controller_ssh.py covers this file now, with an empty
# allow-list.
# ─────────────────────────────────────────────────────────────────────────





# ── Commands ────────────────────────────────────────────────────────


@cluster_app.command("init-secret")
def init_secret():
    """Generate a shared secret for inter-node cluster authentication.

    Prints a random secret that should be set as NOO_CLUSTER_SECRET
    in the controller's .env and all worker .env files.

    If NOO_CLUSTER_SECRET is not set, cluster auth is disabled (backward compatible).
    """
    from .cluster_auth import generate_cluster_secret

    secret = generate_cluster_secret()
    console.print("\n[bold cyan]Cluster Authentication Secret[/bold cyan]\n")
    console.print(f"  [bold]{secret}[/bold]\n")
    console.print("Add this to your controller .env and worker .env files:")
    console.print(f"  [green]NOO_CLUSTER_SECRET={secret}[/green]\n")
    console.print("[dim]If NOO_CLUSTER_SECRET is unset, cluster auth is disabled.[/dim]")


@cluster_app.command("status")
def cluster_status():
    """Show cluster status and all nodes."""
    gateway_url = get_gateway_url()
    try:
        with console.status("Reaching cluster nodes..."):
            response = httpx.get(f"{gateway_url}/api/cluster/nodes", timeout=10.0, **cli_httpx_kwargs())
            response.raise_for_status()
            data = response.json()

        stats = data.get("stats", {})
        nodes = data.get("nodes", [])

    except Exception as e:
        print_error(f"Failed to connect to gateway: {e}")
        print_warning(f"Make sure gateway is running at {gateway_url}")
        raise typer.Exit(1)

    if is_json_output():
        output_json(data)
        return

    # Overall stats
    console.print("\n[bold cyan]📊 Cluster Status[/bold cyan]\n")
    table = Table(show_header=False)
    table.add_row("Total Nodes", str(stats.get("total_nodes", 0)))
    table.add_row("Online", f"[green]{stats.get('online', 0)}[/green]")
    table.add_row("Busy", f"[yellow]{stats.get('busy', 0)}[/yellow]")
    table.add_row("Offline", f"[red]{stats.get('offline', 0)}[/red]")
    table.add_row("Total VRAM", f"{stats.get('total_vram_gb', 0.0):.1f} GB")
    console.print(table)

    # Node list
    console.print("\n[bold cyan]💻 Nodes[/bold cyan]\n")
    nodes_table = Table()
    nodes_table.add_column("Node ID", style="cyan", no_wrap=True)
    nodes_table.add_column("IP", style="dim", no_wrap=True)
    nodes_table.add_column("Status", no_wrap=True)
    nodes_table.add_column("Tier", no_wrap=True)
    nodes_table.add_column("GPU", overflow="fold")
    nodes_table.add_column("VRAM", no_wrap=True)
    nodes_table.add_column("Load", no_wrap=True)
    nodes_table.add_column("Backends", overflow="fold")

    for node in nodes:
        status = node.get("status", "offline")
        status_color = {
            "online": "green",
            "busy": "yellow",
            "offline": "red",
            "maintenance": "blue",
            "quarantined": "magenta",
        }.get(status, "white")

        # Build backend/model display: "vllm (mistral-7b)" instead of just "vllm"
        running = node.get("running_backends", {})
        # Handle both dict (new) and list (old) formats for backwards compat
        if isinstance(running, list):
            running = {b: "" for b in running}
        backend_display = []
        for backend, model in running.items():
            if model:
                backend_display.append(f"{backend} ({model})")
            else:
                backend_display.append(backend)

        # VRAM display: show used/total if live data available
        vram_gb = node.get("vram_gb", 0.0)
        vram_used = node.get("vram_used_gb")
        if vram_gb > 0:
            vram_str = f"{vram_used:.1f}/{vram_gb:.1f}GB" if vram_used is not None else f"{vram_gb:.1f}GB"
        else:
            vram_str = "-"

        nodes_table.add_row(
            node.get("id", ""),
            node.get("ip_address", node.get("ip", "")),
            f"[{status_color}]{status}[/{status_color}]",
            f"Tier {node.get('tier', 3)}",
            node.get("gpu_model") or "CPU",
            vram_str,
            f"{node.get('load', 0.0) * 100:.0f}%",
            "\n".join(backend_display) or "-",
        )

    console.print(nodes_table)


@cluster_app.command("reconcile-models")
def reconcile_models_cmd(
    models: list[str] = typer.Argument(None, help="Desired models (default: NOO_DESIRED_MODELS)"),
    backend: str = typer.Option("ollama", "--backend", "-b"),
    apply: bool = typer.Option(False, "--apply", help="Place any missing ones (else dry-run)"),
):
    """♻️  Converge the fleet to a desired set of models (idempotent).

    Skips models already running anywhere; plans placement only for the gap.
    Schedule this (cron / heartbeat task) for a self-managing fleet that keeps
    the desired models available with no hand-assignment.
    """
    from .model_placement import reconcile_models

    desired = list(models) or [
        m.strip() for m in os.getenv("NOO_DESIRED_MODELS", "").split(",") if m.strip()
    ]
    if not desired:
        print_error("no desired models (pass them as args or set NOO_DESIRED_MODELS)")
        raise typer.Exit(1)

    gateway_url = get_gateway_url()
    try:
        resp = httpx.get(f"{gateway_url}/api/cluster/nodes", timeout=10.0, **cli_httpx_kwargs())
        resp.raise_for_status()
        nodes = resp.json().get("nodes", [])
    except Exception as e:
        print_error(f"Failed to reach gateway: {e}")
        raise typer.Exit(1)

    plan = reconcile_models(desired, nodes)
    if is_json_output():
        output_json({"desired": desired, "to_place": plan})
        return
    if not plan:
        print_success(f"fleet already satisfies the desired set ({len(desired)} models)")
        return

    console.print(f"[bold]{len(plan)} model(s) need placing:[/bold]")
    ok = True
    for p in plan:
        if "error" in p:
            print_error(f"{p['model']}: {p['error']}")
            ok = False
            continue
        pull = " (pull)" if p.get("needs_pull") else ""
        console.print(f"→ {p['model']}  →  [bold]{p['node_id']}[/bold]{pull}  ({p['reason']})")
    if not apply:
        console.print("  [dim](dry-run — pass --apply to converge)[/dim]")
        raise typer.Exit(0 if ok else 1)
    for p in plan:
        if "error" in p:
            continue
        try:
            r = httpx.post(
                f"{gateway_url}/api/cluster/backends/start",
                json={"backend": backend, "model": p["model"], "node_id": p["node_id"]},
                timeout=60.0, **cli_httpx_kwargs(),
            )
            r.raise_for_status()
            print_success(f"{p['model']} → {p['node_id']}")
        except Exception as e:
            print_error(f"{p['model']} placement failed: {e}")
            ok = False
    raise typer.Exit(0 if ok else 1)




@cluster_app.command("auto-place")
def auto_place(
    models: list[str] = typer.Argument(..., help="Models to place across the fleet"),
    backend: str = typer.Option("ollama", "--backend", "-b"),
    apply: bool = typer.Option(False, "--apply", help="Actually place them (else dry-run)"),
):
    """🤖 Place a SET of models across the fleet by capability × availability.

    Runs the matcher for each model, spreading them across nodes (each placement
    bumps that node's load so the next model prefers a different node). Dry-run
    unless --apply. This is the hands-off, whole-fleet version of place-model.
    """
    from .model_placement import plan_model_placements

    gateway_url = get_gateway_url()
    try:
        resp = httpx.get(f"{gateway_url}/api/cluster/nodes", timeout=10.0, **cli_httpx_kwargs())
        resp.raise_for_status()
        nodes = resp.json().get("nodes", [])
    except Exception as e:
        print_error(f"Failed to reach gateway: {e}")
        raise typer.Exit(1)

    plan = plan_model_placements(list(models), nodes)
    if is_json_output():
        output_json(plan)
        return

    ok = True
    for p in plan:
        if "error" in p:
            print_error(f"{p['model']}: {p['error']}")
            ok = False
            continue
        pull = " (pull)" if p.get("needs_pull") else ""
        console.print(f"→ {p['model']}  →  [bold]{p['node_id']}[/bold]{pull}  ({p['reason']})")
    if not apply:
        console.print("  [dim](dry-run — pass --apply to place them)[/dim]")
        raise typer.Exit(0 if ok else 1)

    for p in plan:
        if "error" in p:
            continue
        try:
            r = httpx.post(
                f"{gateway_url}/api/cluster/backends/start",
                json={"backend": backend, "model": p["model"], "node_id": p["node_id"]},
                timeout=60.0, **cli_httpx_kwargs(),
            )
            r.raise_for_status()
            print_success(f"{p['model']} → {p['node_id']}")
        except Exception as e:
            print_error(f"{p['model']} placement failed: {e}")
            ok = False
    raise typer.Exit(0 if ok else 1)


@cluster_app.command("place-model")
def place_model(
    model: str = typer.Argument(..., help="Model id to place (e.g. google/gemma-4-12B-it)"),
    backend: str = typer.Option("ollama", "--backend", "-b", help="Backend to run it on"),
    apply: bool = typer.Option(False, "--apply", help="Actually place it (else dry-run)"),
):
    """🎯 Pick the best node for a model by capability × cached availability.

    Reads the live fleet (VRAM + each node's reported model inventory) and the
    catalog's VRAM estimate, then selects the node that already has the model
    (or the best-fit capable node + a pull). Dry-run unless --apply.
    """
    from .model_placement import match_node_for_model

    gateway_url = get_gateway_url()
    try:
        response = httpx.get(f"{gateway_url}/api/cluster/nodes", timeout=10.0, **cli_httpx_kwargs())
        response.raise_for_status()
        nodes = response.json().get("nodes", [])
    except Exception as e:
        print_error(f"Failed to reach gateway: {e}")
        raise typer.Exit(1)

    decision = match_node_for_model(model, nodes)
    if is_json_output():
        output_json(decision)
        return
    if "error" in decision:
        print_error(decision["error"])
        raise typer.Exit(1)

    node = decision["node_id"]
    console.print(f"→ place [bold cyan]{model}[/bold cyan] on [bold]{node}[/bold]  ({decision['reason']})")
    if decision["needs_pull"]:
        console.print(f"  needs pull: model not cached on {node}")
    if not apply:
        console.print("  [dim](dry-run — pass --apply to place it)[/dim]")
        return
    console.print(f"  placing via: noo cluster up {backend} {model} --node {node}")
    try:
        r = httpx.post(
            f"{gateway_url}/api/cluster/backends/start",
            json={"backend": backend, "model": model, "node_id": node},
            timeout=60.0, **cli_httpx_kwargs(),
        )
        r.raise_for_status()
        print_success(f"placement requested on {node}")
    except Exception as e:
        print_error(f"placement failed: {e}")
        raise typer.Exit(1)


@cluster_app.command("up")
def start_backend(
    backend: str = typer.Argument(..., help="Backend to start (vllm, llamacpp, airllm, ollama)",
                                  autocompletion=_complete_backends),
    model: str = typer.Argument(..., help="Model to load",
                                autocompletion=_complete_model_files),
    node: str = typer.Option(None, help="Specific node ID to use",
                             autocompletion=_complete_node_ids),
    replicas: int = typer.Option(1, help="Number of replicas to start"),
):
    """🚀 Start a backend with model on a node.

    Examples:
        noo cluster up vllm google/gemma-2-2b-it
        noo cluster up llamacpp llama-7b-Q5_K_M --replicas 2
        noo cluster up airllm llama-70b --node gpu-node-1
    """
    gateway_url = get_gateway_url()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"Starting {backend} with {model}...", total=None)

        for i in range(replicas):
            try:
                # Call gateway API to start backend
                response = httpx.post(
                    f"{gateway_url}/api/cluster/backends/start",
                    json={
                        "backend": backend,
                        "model": model,
                        "node_id": node,
                    },
                    timeout=60.0,
                    **cli_httpx_kwargs(),
                )
                response.raise_for_status()
                result = response.json()

                node_label = result.get('node_hostname', result.get('node_id', '?'))
                node_ip = result.get('ip_address', '')
                if node_ip:
                    node_label = f"{node_label} ({node_ip})"
                print_success(f"Started {backend} ({model}) on {node_label}")

            except httpx.HTTPStatusError as e:
                error_detail = e.response.json().get("detail", str(e))
                print_error(f"Failed to start: {error_detail}")
                raise typer.Exit(1)
            except Exception as e:
                print_error(f"Failed to start: {e}")
                raise typer.Exit(1)


@cluster_app.command("down")
def stop_backend(
    backend: str = typer.Argument(..., help="Backend to stop",
                                  autocompletion=_complete_backends),
    node: str = typer.Option(None, help="Node ID (stops on all nodes if not specified)",
                             autocompletion=_complete_node_ids),
):
    """⏹️  Stop a backend.

    Examples:
        noo cluster down vllm --node gpu-node-1
        noo cluster down llamacpp  # Stops on all nodes
    """
    target = f"{backend} on {node}" if node else f"{backend} on all nodes"
    confirm_destructive("stop backend", target)

    gateway_url = get_gateway_url()
    try:
        with console.status(f"Stopping {backend}..."):
            response = httpx.post(
                f"{gateway_url}/api/cluster/backends/stop",
                json={
                    "backend": backend,
                    "node_id": node,
                },
                timeout=60.0,
                **cli_httpx_kwargs(),
            )
            response.raise_for_status()
            result = response.json()

        if result["status"] == "not_running":
            print_warning(f"{backend} not running on any nodes")
        else:
            print_success(f"Stopped {backend} on {result['stopped_count']} node(s)")

    except httpx.HTTPStatusError as e:
        error_detail = e.response.json().get("detail", str(e))
        print_error(f"Failed to stop: {error_detail}")
        raise typer.Exit(1)
    except Exception as e:
        print_error(f"Failed to stop: {e}")
        raise typer.Exit(1)


@cluster_app.command("restart-agent")
def restart_node_agent(
    node: str = typer.Argument(..., help="Node ID to restart agent on",
                               autocompletion=_complete_node_ids),
):
    """🔄 Restart the node-agent on a remote node.

    This triggers the node-agent to restart, which will re-register with the gateway.

    Examples:
        noo cluster restart-agent mobile-compute
    """
    gateway_url = get_gateway_url()
    try:
        with console.status(f"Restarting node-agent on {node}..."):
            response = httpx.post(
                f"{gateway_url}/api/cluster/nodes/{node}/restart-agent",
                timeout=30.0,
                **cli_httpx_kwargs(),
            )
            response.raise_for_status()
            result = response.json()

        print_success(result.get("message", "Agent restart triggered"))

    except httpx.HTTPStatusError as e:
        error_detail = e.response.json().get("detail", str(e)) if e.response.content else str(e)
        print_error(f"Failed to restart: {error_detail}")
        raise typer.Exit(1)
    except Exception as e:
        print_error(f"Failed to restart: {e}")
        raise typer.Exit(1)




@cluster_app.command("assign")
def assign_task(
    task: str = typer.Argument(..., help="Task description or prompt"),
    node: str = typer.Option(None, help="Specific node to assign to"),
    backend: str = typer.Option(None, help="Specific backend to use"),
    priority: str = typer.Option("medium", help="Task priority (low, medium, high)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show routing decision without executing"),
):
    """📋 Assign a task to a node for inference.

    Examples:
        noo cluster assign "Analyze this dataset" --backend vllm --priority high
        noo cluster assign "Background research" --priority low --node cpu-node-1
        noo cluster assign "Summarize this" --dry-run
    """
    gateway_url = get_gateway_url()

    if dry_run:
        # Show which node/backend would be selected without executing
        nodes = _get_online_nodes()
        if not nodes:
            fatal("No online nodes available")

        # Filter by requested node
        if node:
            nodes = [n for n in nodes if n.get("id") == node or n.get("hostname") == node]
            if not nodes:
                fatal(f"Node '{node}' not found or offline")

        # Filter by requested backend
        if backend:
            matching = [
                n for n in nodes
                if backend in (n.get("running_backends") or {})
            ]
            if matching:
                nodes = matching
            else:
                print_warning(f"No nodes currently running {backend}")

        # Pick least loaded
        nodes.sort(key=lambda n: n.get("load", 1.0))
        selected = nodes[0]

        running = selected.get("running_backends", {})
        if isinstance(running, list):
            running = {b: "" for b in running}

        console.print("\n[bold cyan]Routing decision (dry run)[/bold cyan]\n")
        table = Table(show_header=False)
        table.add_row("Node", selected.get("id", "?"))
        table.add_row("Tier", f"Tier {selected.get('tier', 3)}")
        table.add_row("GPU", selected.get("gpu_model") or "CPU")
        table.add_row("Load", f"{selected.get('load', 0.0) * 100:.0f}%")
        table.add_row("Running backends", ", ".join(running.keys()) or "none")
        table.add_row("Backend", backend or "auto")
        table.add_row("Priority", priority)
        console.print(table)
        return

    # Execute inference via gateway
    try:
        with console.status("Sending task to cluster..."):
            payload = {
                "prompt": task,
            }
            if backend:
                payload["backend"] = backend
            if node:
                payload["node_id"] = node

            response = httpx.post(
                f"{gateway_url}/api/chat/completions",
                json=payload,
                timeout=120.0,
                **cli_httpx_kwargs(),
            )
            response.raise_for_status()
            result = response.json()

        print_success("Task completed")
        # Display the response
        if "choices" in result:
            for choice in result["choices"]:
                msg = choice.get("message", {}).get("content", "")
                if msg:
                    console.print(f"\n{msg}")
        elif "response" in result:
            console.print(f"\n{result['response']}")
        else:
            console.print(result)

    except httpx.HTTPStatusError as e:
        error_detail = e.response.json().get("detail", str(e)) if e.response.content else str(e)
        print_error(f"Task failed: {error_detail}")
        raise typer.Exit(1)
    except Exception as e:
        print_error(f"Task failed: {e}")
        raise typer.Exit(1)


@cluster_app.command("scale")
def scale_backend(
    backend: str = typer.Argument(..., help="Backend to scale"),
    replicas: int = typer.Option(..., "--replicas", "-r", help="Target number of replicas"),
    model: str = typer.Option("default", "--model", "-m", help="Model to use when scaling up"),
):
    """⚡ Scale a backend up or down.

    Examples:
        noo cluster scale vllm --replicas 3 --model google/gemma-2-2b-it
        noo cluster scale llamacpp -r 1
    """
    gateway_url = get_gateway_url()

    # Count current replicas via gateway API
    try:
        response = httpx.get(f"{gateway_url}/api/cluster/nodes", timeout=10.0, **cli_httpx_kwargs())
        response.raise_for_status()
        nodes = response.json().get("nodes", [])
    except Exception as e:
        fatal(f"Failed to reach gateway: {e}")

    current_replicas = 0
    nodes_with_backend = []
    for n in nodes:
        running = n.get("running_backends", {})
        if isinstance(running, list):
            running = {b: "" for b in running}
        if backend in running:
            current_replicas += 1
            nodes_with_backend.append(n)

    console.print(f"Current replicas: {current_replicas}")
    console.print(f"Target replicas: {replicas}")

    if replicas > current_replicas:
        # Scale up via gateway API (same as `cluster up`)
        to_start = replicas - current_replicas
        print_info(f"Scaling up by {to_start}...")

        for i in range(to_start):
            try:
                response = httpx.post(
                    f"{gateway_url}/api/cluster/backends/start",
                    json={"backend": backend, "model": model},
                    timeout=60.0,
                    **cli_httpx_kwargs(),
                )
                response.raise_for_status()
                result = response.json()
                print_success(f"Started replica on {result.get('node_hostname', '?')}")
            except httpx.HTTPStatusError as e:
                error_detail = e.response.json().get("detail", str(e))
                print_warning(f"Could not start replica {i + 1}: {error_detail}")
                break
            except Exception as e:
                print_warning(f"Could not start replica {i + 1}: {e}")
                break

    elif replicas < current_replicas:
        # Scale down via gateway API (same as `cluster down`)
        to_stop = current_replicas - replicas
        confirm_destructive("scale down", f"{backend} by {to_stop} replica(s)")
        print_info(f"Scaling down by {to_stop}...")

        # Stop least loaded nodes first
        nodes_with_backend.sort(key=lambda n: n.get("load", 0.0))

        for n in nodes_with_backend[:to_stop]:
            try:
                response = httpx.post(
                    f"{gateway_url}/api/cluster/backends/stop",
                    json={"backend": backend, "node_id": n.get("id")},
                    timeout=60.0,
                    **cli_httpx_kwargs(),
                )
                response.raise_for_status()
                print_success(f"Stopped replica on {n.get('id', '?')}")
            except Exception as e:
                print_warning(f"Failed to stop on {n.get('id', '?')}: {e}")

    else:
        print_success("Already at target replica count")









def _controller_ssh_pubkey() -> str:
    """First available SSH public key of the controller operator."""
    ssh_dir = Path.home() / ".ssh"
    for name in ("id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"):
        pub = ssh_dir / name
        if pub.exists():
            return pub.read_text().strip()
    return ""


@cluster_app.command("mint-join-key")
def mint_join_key(
    tag: str = typer.Option("tag:worker", "--tag", help="Tailscale ACL tag applied to the joining node"),
    expiry_minutes: int = typer.Option(60, "--expiry-minutes", help="How long the key stays redeemable"),
    reusable: bool = typer.Option(False, "--reusable", help="Allow the key to enroll multiple nodes"),
    ssh_user: str = typer.Option(None, "--ssh-user", help="Remote username to authorize SSH for (shown in the one-liner)"),
    script_url: str = typer.Option(None, "--script-url", help="Override the bootstrap script URL"),
):
    """🔑 Mint a Tailscale join key for enrolling a remote node.

    Creates a single-use, pre-authorized, tagged Tailscale auth key and
    prints the bootstrap one-liner to send to the remote node's owner.
    Once they run it and send back their overlay IP (100.x.y.z), finish
    with: noo cluster provision <node-name> --wait

    Requires NOO_TAILSCALE_API_KEY (create one in the Tailscale admin
    console under Settings → Keys and store it via `sops secrets/env.sops`
    — never .env). The tag must be declared in your tailnet ACL policy's
    tagOwners section.
    """
    # Shared with the gateway/MCP surface (noo_mint_join_key tool) — one
    # source of truth for the Tailscale API call and one-liner composition.
    from .tailscale import TailscaleError, mint_join_key as _mint

    if script_url:  # explicit flag beats env resolution inside the module
        os.environ["NOO_BOOTSTRAP_SCRIPT_URL"] = script_url

    pubkey = _controller_ssh_pubkey()
    if not pubkey:
        print_warning("No SSH public key found in ~/.ssh — the remote owner must authorize SSH manually.")

    try:
        result = _mint(tag=tag, expiry_minutes=expiry_minutes, reusable=reusable,
                       ssh_user=ssh_user, ssh_pubkey=pubkey or None)
    except TailscaleError as e:
        print_error(str(e))
        console.print(
            "\nOne-time setup:\n"
            "  1. Tailscale admin console → Settings → Keys → Generate API key\n"
            "  2. Store it: sops secrets/env.sops → add "
            "NOO_TAILSCALE_API_KEY=tskey-api-...  (never .env)\n"
            "  3. Declare the tag in your ACL policy, e.g.\n"
            '     "tagOwners": {"tag:worker": ["autogroup:admin"]}\n'
        )
        raise typer.Exit(1)
    except httpx.HTTPError as e:
        print_error(f"Could not reach the Tailscale API: {e}")
        raise typer.Exit(1)

    one_liner = result["one_liner"]
    resolved_url = result["script_url"]

    # If the script URL isn't fetchable (private repo, not yet synced), fall
    # back to sending the script file itself — it is self-contained.
    url_ok = False
    try:
        url_ok = httpx.head(resolved_url, timeout=5, follow_redirects=True).status_code == 200
    except httpx.HTTPError:
        pass

    console.print(f"\n[bold green]✓ Join key minted[/bold green] "
                  f"(single-use={not reusable}, expires in {expiry_minutes} min, tag={tag})\n")
    if url_ok:
        console.print("Send this command to the remote node's owner:\n")
    else:
        # scripts/bootstrap-node.sh is retired and no longer in
        # the tree, so there is no local file to hand over instead.
        print_warning(f"Bootstrap script URL is not reachable ({resolved_url}).")
        console.print(
            "\nThis pre-token lane is retired. Enroll the node over the pull"
            " rail instead: noo cluster bootstrap-token create --node <name>\n"
        )
    # soft_wrap: never hard-wrap the command — a copied wrapped line pastes
    # as broken multi-line garbage on the remote node
    console.print(one_liner, style="bold cyan", soft_wrap=True)
    console.print()
    if _copy_to_clipboard(one_liner):
        console.print("[green]✓ Copied to clipboard[/green] — paste it directly "
                      "into a message or the node's terminal.\n")
    console.print(
        "When they send back the node's overlay IP (100.x.y.z), finish with:\n"
        "  [cyan]noo cluster provision <node-name> --wait[/cyan]\n"
    )


PRIMARY_ALIAS = "noo-controller"  # Tailscale device name held by the primary


def _copy_to_clipboard(text: str) -> bool:
    """Best-effort copy to the system clipboard (WSL/mac/Wayland/X11)."""
    import shutil
    for cmd in (["clip.exe"], ["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), check=True, timeout=5)
                return True
            except Exception:
                continue
    return False










@cluster_app.command("add-companion")
def add_companion(
    node_id: str = typer.Argument(..., help="Unique ID for the companion device (e.g. phone-1)"),
    platform: str = typer.Option("android", "--platform", "-p", help="Platform: android, ios, linux"),
    hostname: str = typer.Option(None, "--hostname", help="Friendly hostname (defaults to node_id)"),
    ip: str = typer.Option("0.0.0.0", "--ip", help="Device IP (informational — companions self-report)"),
    sensors: str = typer.Option("", "--sensors", "-s", help="Comma-separated sensors: camera,gps,mic,clipboard,screen"),
    backends: str = typer.Option("llamacpp", "--backends", "-b", help="Comma-separated backends: llamacpp"),
    battery: float = typer.Option(100.0, "--battery", help="Initial battery percentage (0-100)"),
    network: str = typer.Option("wifi", "--network", "-n", help="Network type: wifi, ethernet, cellular, offline"),
    npu_tops: float = typer.Option(0.0, "--npu-tops", help="NPU performance in TOPS"),
    app_version: str = typer.Option("cli-manual", "--app-version", help="Companion app version"),
):
    """📱 Register a companion (Tier 5) device.

    Companion devices are phones, tablets, or other battery-powered devices
    that provide sensor context (camera, GPS, mic) and optionally run small
    models (1-3B). Unlike worker nodes, companions are not SSH-provisioned —
    they self-register via the gateway API.

    This command manually registers a companion for testing or when the
    companion app isn't available. In production, the companion app calls
    the same registration endpoint automatically.

    Examples:
        noo cluster add-companion phone-1 --platform android --sensors camera,gps,mic
        noo cluster add-companion tablet-1 -p ios -s camera,clipboard,screen --battery 85
        noo cluster add-companion rpi-zero --platform linux --sensors mic --backends llamacpp
        noo cluster add-companion pixel-9 -p android -s camera,gps,mic --npu-tops 60
    """
    gateway_url = get_gateway_url()
    hostname = hostname or node_id
    sensor_list = [s.strip() for s in sensors.split(",") if s.strip()]
    backend_list = [b.strip() for b in backends.split(",") if b.strip()]

    payload = {
        "node_id": node_id,
        "hostname": hostname,
        "ip_address": ip,
        "capabilities": {
            "cpu_cores": 4,
            "ram_gb": 4.0,
            "gpu_model": None,
            "vram_gb": 0.0,
            "is_arm": platform in ("android", "ios"),
            "backends": backend_list,
            "tools": [],
            "tier": 5,
            "npu_tops": npu_tops,
            "platform": platform,
            "app_version": app_version,
            "sensors": sensor_list,
            "power_budget_watts": 5.0,
        },
    }

    try:
        with console.status(f"Registering companion device [cyan]{node_id}[/]..."):
            resp = httpx.post(
                f"{gateway_url}/api/cluster/nodes/register",
                json=payload,
                timeout=10.0,
                **cli_httpx_kwargs(),
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        detail = e.response.json().get("detail", str(e)) if e.response.content else str(e)
        print_error(f"Registration failed: {detail}")
        raise typer.Exit(1)
    except Exception as e:
        fatal(f"Cannot reach gateway at {gateway_url}: {e}")

    if is_json_output():
        output_json(resp.json())
        return

    console.print("\n[bold green]✓ Companion device registered[/bold green]\n")

    table = Table(title="Companion Device", show_header=False)
    table.add_row("Node ID", node_id)
    table.add_row("Platform", platform)
    table.add_row("Hostname", hostname)
    table.add_row("Sensors", ", ".join(sensor_list) if sensor_list else "none")
    table.add_row("Backends", ", ".join(backend_list))
    table.add_row("Battery", f"{battery:.0f}%")
    table.add_row("Network", network)
    if npu_tops > 0:
        table.add_row("NPU", f"{npu_tops:.0f} TOPS")
    table.add_row("Tier", "Tier 5 (Companion)")
    console.print(table)

    # Send initial heartbeat so device shows as online
    try:
        hb_resp = httpx.post(
            f"{gateway_url}/api/cluster/nodes/{node_id}/heartbeat",
            json={
                "load": 0.0,
                "running_backends": {},
                "battery_pct": battery,
                "is_charging": True,
                "network_type": network,
                "thermal_state": "nominal",
                "active_sensors": sensor_list,
            },
            timeout=5.0,
            **cli_httpx_kwargs(),
        )
        if hb_resp.status_code == 200:
            console.print("[dim]Initial heartbeat sent — device is online.[/dim]")
    except Exception:
        print_warning("Initial heartbeat failed — device will appear offline until it sends a heartbeat.")

    console.print("\n[bold]Next steps:[/bold]")
    console.print("1. Check status: [cyan]noo cluster status[/cyan]")
    if sensor_list:
        console.print(f"2. Sensor tools auto-registered: {', '.join(sensor_list)}")
    console.print(f"{'3' if sensor_list else '2'}. Send heartbeats to keep device online (10-min timeout)")


@cluster_app.command("add-monitor")
def add_monitor(
    node_id: str = typer.Argument(..., help="Unique ID for the monitor node (e.g. meshsec-pi)"),
    hostname: str = typer.Option(None, "--hostname", help="Friendly hostname (defaults to node_id)"),
    ip: str = typer.Option("0.0.0.0", "--ip", help="Device IP address"),
    services: str = typer.Option("", "--services", "-s", help="Comma-separated monitoring services: meshsec,prometheus,alertmanager,blackbox"),
):
    """🔍 Register a dedicated monitoring (Tier 6) node.

    Monitor nodes run security scanning, network probes, and observability
    tools (e.g. meshsec, Prometheus, Blackbox Exporter). They don't run
    inference backends and are excluded from compute scheduling.

    Examples:
        noo cluster add-monitor meshsec-pi --ip 10.0.1.20 --services meshsec
        noo cluster add-monitor obs-node --ip 10.0.1.21 -s prometheus,alertmanager
    """
    gateway_url = get_gateway_url()
    hostname = hostname or node_id
    service_list = [s.strip() for s in services.split(",") if s.strip()]

    payload = {
        "node_id": node_id,
        "hostname": hostname,
        "ip_address": ip,
        "capabilities": {
            "cpu_cores": 4,
            "ram_gb": 2.0,
            "gpu_model": None,
            "vram_gb": 0.0,
            "is_arm": True,
            "backends": [],
            "tools": service_list,
            "tier": 6,
        },
    }

    try:
        with console.status(f"Registering monitor node [cyan]{node_id}[/]..."):
            resp = httpx.post(
                f"{gateway_url}/api/cluster/nodes/register",
                json=payload,
                timeout=10.0,
                **cli_httpx_kwargs(),
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        detail = e.response.json().get("detail", str(e)) if e.response.content else str(e)
        print_error(f"Registration failed: {detail}")
        raise typer.Exit(1)
    except Exception as e:
        fatal(f"Cannot reach gateway at {gateway_url}: {e}")

    if is_json_output():
        output_json(resp.json())
        return

    console.print("\n[bold green]✓ Monitor node registered[/bold green]\n")

    table = Table(title="Monitor Node", show_header=False)
    table.add_row("Node ID", node_id)
    table.add_row("Hostname", hostname)
    table.add_row("IP", ip)
    table.add_row("Services", ", ".join(service_list) if service_list else "none")
    table.add_row("Tier", "Tier 6 (Monitor)")
    console.print(table)

    # Send initial heartbeat
    try:
        hb_resp = httpx.post(
            f"{gateway_url}/api/cluster/nodes/{node_id}/heartbeat",
            json={"load": 0.0, "running_backends": {}},
            timeout=5.0,
            **cli_httpx_kwargs(),
        )
        if hb_resp.status_code == 200:
            console.print("[dim]Initial heartbeat sent — node is online.[/dim]")
    except Exception:
        print_warning("Initial heartbeat failed — node will appear offline until it sends a heartbeat.")

    console.print("\n[bold]Next steps:[/bold]")
    console.print("1. Check status: [cyan]noo cluster status[/cyan]")
    if service_list:
        console.print(f"2. Services registered: {', '.join(service_list)}")
    console.print(f"{'3' if service_list else '2'}. Deploy monitoring tools to the node")




# ── Desired-state config (DESIRED_STATE_CONFIG.md) ──────────────────


@cluster_app.command("desired")
def desired_config(
    node: str = typer.Argument(..., help="Node ID", autocompletion=_complete_node_ids),
):
    """📋 Show a node's DB-backed desired config + backend placements.

    This is the authoritative state the node-agent reconciles toward
    (every 5 min): models dir ownership, which backends run, with which
    model/port. Change it with set-config / place / unplace.
    """
    gateway_url = get_gateway_url()
    try:
        r = httpx.get(f"{gateway_url}/api/cluster/nodes/{node}/desired-config",
                      timeout=10.0, **cli_httpx_kwargs())
        r.raise_for_status()
    except Exception as e:
        fatal(f"Failed to fetch desired config: {e}")
    data = r.json()
    if is_json_output():
        output_json(data)
        return
    n = data.get("node")
    if not n:
        print_warning(f"No config row for '{node}' — seed with: "
                      f"noo cluster set-config {node} --data-root <path>")
    else:
        console.print(f"[bold]{node}[/] ip={n.get('ip_address')} tier={n.get('tier')} "
                      f"ssh_user={n.get('ssh_user')}")
        console.print(f"  data_root:  {n.get('data_root')}")
        console.print(f"  models_dir: {n.get('models_dir')}")
        if n.get("gpu_model") or n.get("vram_gb"):
            console.print(f"  gpu override: {n.get('gpu_model')} ({n.get('vram_gb')} GB)"
                          + ("" if n.get("gpu_model") and n.get("vram_gb")
                             else "  [yellow](inactive — needs BOTH gpu-model and vram-gb)[/yellow]"))
    placements = data.get("placements", [])
    if not placements:
        console.print("  (no placements)")
        return
    table = Table(title="Placements")
    for col in ("backend", "model", "port", "tls", "env", "desired"):
        table.add_column(col)
    for p in placements:
        env_map = p.get("env") or {}
        env_str = " ".join(f"{k}={v}" for k, v in sorted(env_map.items())) \
            if isinstance(env_map, dict) else str(env_map)
        table.add_row(p.get("backend", ""), str(p.get("model", "")),
                      str(p.get("port", "")), str(p.get("tls", "")),
                      env_str,
                      p.get("desired_state", ""))
    console.print(table)


@cluster_app.command("set-config")
def set_node_config(
    node: str = typer.Argument(..., help="Node ID", autocompletion=_complete_node_ids),
    data_root: str = typer.Option(None, "--data-root", help="Node data root (models_dir defaults to <root>/models)"),
    models_dir: str = typer.Option(None, "--models-dir", help="Explicit models directory"),
    ssh_user: str = typer.Option(None, "--ssh-user"),
    ip: str = typer.Option(None, "--ip"),
    tier: int = typer.Option(None, "--tier"),
    gpu_model: str = typer.Option(None, "--gpu-model", help="GPU override for broken detection (needs --vram-gb too)"),
    vram_gb: float = typer.Option(None, "--vram-gb", help="VRAM override in GB (needs --gpu-model too)"),
):
    """⚙️  Upsert a node's desired config (DB-backed; replaces node .env drift).

    The GPU override beats the node's self-detection only when BOTH
    --gpu-model and --vram-gb are set (a GPU claim without VRAM isn't
    advertised). Applied by the gateway on the node's next heartbeat.
    """
    body = {k: v for k, v in {
        "data_root": data_root, "models_dir": models_dir,
        "ssh_user": ssh_user, "ip_address": ip, "tier": tier,
        "gpu_model": gpu_model, "vram_gb": vram_gb,
    }.items() if v is not None}
    if not body:
        fatal("Nothing to set — pass at least one option")
    gateway_url = get_gateway_url()
    try:
        r = httpx.put(f"{gateway_url}/api/cluster/nodes/{node}/config",
                      json=body, timeout=10.0, **cli_httpx_kwargs())
        r.raise_for_status()
    except Exception as e:
        fatal(f"Failed to update config: {e}")
    print_success(f"{node}: config updated — agent reconciles within 5 min")


@cluster_app.command("seed")
def seed_cluster(
    file: Path = typer.Option(
        Path("config/cluster-seed.yaml"), "--file", "-f",
        help="Seed file (gitignored; see config/cluster-seed.yaml.example)"),
    export: bool = typer.Option(
        False, "--export",
        help="Write the CURRENT desired state from the DB into the seed file instead of applying"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be applied without writing"),
):
    """🌱 Apply (or export) the whole cluster's desired state from a local seed file.

    The seed file holds your node configs + backend placements (IPs, ssh
    users, data roots) and is gitignored — machine-specific truth never
    lives in the repo or in migrations. Apply after a fresh install:

      noo cluster seed              # applies config/cluster-seed.yaml
      noo cluster seed --export     # snapshot current DB state to the file
    """
    import yaml

    gateway_url = get_gateway_url()

    if export:
        try:
            r = httpx.get(f"{gateway_url}/api/cluster/nodes", timeout=10.0, **cli_httpx_kwargs())
            r.raise_for_status()
            node_ids = sorted({n.get("node_id") or n.get("id") for n in r.json().get("nodes", [])} - {None})
        except Exception as e:
            fatal(f"Failed to list nodes: {e}")
        doc = {"nodes": {}, "placements": []}
        for nid in node_ids:
            try:
                r = httpx.get(f"{gateway_url}/api/cluster/nodes/{nid}/desired-config",
                              timeout=10.0, **cli_httpx_kwargs())
                r.raise_for_status()
            except Exception as e:
                print_warning(f"{nid}: could not fetch desired config ({e}); skipping")
                continue
            data = r.json()
            n = data.get("node")
            if n:
                doc["nodes"][nid] = {k: v for k, v in {
                    "ip": n.get("ip_address"), "ssh_user": n.get("ssh_user"),
                    "tier": n.get("tier"), "data_root": n.get("data_root"),
                    "models_dir": n.get("models_dir"),
                    "gpu_model": n.get("gpu_model"), "vram_gb": n.get("vram_gb"),
                }.items() if v is not None}
            for p in data.get("placements", []):
                doc["placements"].append({k: v for k, v in {
                    "node": nid, "backend": p.get("backend"), "model": p.get("model"),
                    "port": p.get("port"), "tls": p.get("tls") or None,
                    "image": p.get("image"),
                    "env": p.get("env") or None,  # omit when empty/absent
                    "state": p.get("desired_state"),
                }.items() if v is not None})
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(yaml.safe_dump(doc, sort_keys=False))
        print_success(f"Exported desired state for {len(doc['nodes'])} node(s) → {file}")
        return

    if not file.exists():
        fatal(f"Seed file not found: {file} — copy config/cluster-seed.yaml.example "
              f"and fill in your nodes, or snapshot a live cluster with --export")
    try:
        doc = yaml.safe_load(file.read_text()) or {}
    except Exception as e:
        fatal(f"Failed to parse {file}: {e}")

    nodes = doc.get("nodes") or {}
    placements = doc.get("placements") or []
    for nid, cfg in nodes.items():
        body = {k: v for k, v in {
            "data_root": cfg.get("data_root"), "models_dir": cfg.get("models_dir"),
            "ssh_user": cfg.get("ssh_user"), "ip_address": cfg.get("ip"),
            "tier": cfg.get("tier"),
            "gpu_model": cfg.get("gpu_model"), "vram_gb": cfg.get("vram_gb"),
        }.items() if v is not None}
        if dry_run:
            print_info(f"[dry-run] set-config {nid}: {body}")
            continue
        try:
            r = httpx.put(f"{gateway_url}/api/cluster/nodes/{nid}/config",
                          json=body, timeout=10.0, **cli_httpx_kwargs())
            r.raise_for_status()
            print_success(f"{nid}: config applied")
        except Exception as e:
            print_error(f"{nid}: config failed ({e})")
    for p in placements:
        nid, backend = p.get("node"), p.get("backend")
        if not nid or not backend:
            print_warning(f"Skipping placement missing node/backend: {p}")
            continue
        body = {"model": p.get("model"), "tls": bool(p.get("tls", False)),
                "desired_state": p.get("state", "running")}
        if p.get("port") is not None:
            body["port"] = p["port"]
        if p.get("image"):
            body["image"] = p["image"]
        if p.get("env"):
            body["env"] = p["env"]
        if dry_run:
            print_info(f"[dry-run] place {nid}/{backend}: {body}")
            continue
        try:
            r = httpx.put(f"{gateway_url}/api/cluster/nodes/{nid}/placements/{backend}",
                          json=body, timeout=10.0, **cli_httpx_kwargs())
            r.raise_for_status()
            print_success(f"{nid}: {backend} → {p.get('model')} placed")
        except Exception as e:
            print_error(f"{nid}/{backend}: placement failed ({e})")
    if not dry_run:
        print_info("Node-agents reconcile within 5 min")


def _parse_env_options(pairs: list[str] | None) -> dict[str, str]:
    """Parse repeated --env KEY=VALUE options into a dict (fatal on bad input)."""
    env: dict[str, str] = {}
    for item in pairs or []:
        key, sep, value = item.partition("=")
        if not sep or not key:
            fatal(f"Invalid --env '{item}' — expected KEY=VALUE")
        env[key] = value
    return env


@cluster_app.command("place")
def place_backend(
    node: str = typer.Argument(..., help="Node ID", autocompletion=_complete_node_ids),
    backend: str = typer.Argument(..., help="Backend type", autocompletion=_complete_backends),
    model: str = typer.Argument(..., help="Model (gguf filename or HF id)", autocompletion=_complete_model_files),
    port: int = typer.Option(None, "--port", help="Contract port (default per backend)"),
    tls: bool = typer.Option(False, "--tls", help="Backend serves TLS"),
    image: str = typer.Option(None, "--image", help="Image override"),
    env: list[str] = typer.Option(None, "--env", "-e",
        help="Container env var KEY=VALUE (repeatable), e.g. -e VLLM_WSL2_ENABLE_PIN_MEMORY=1"),
    stopped: bool = typer.Option(False, "--stopped", help="Record placement but keep it stopped"),
):
    """📌 Declare that <node> should run <backend> with <model>.

    The node-agent converges within 5 min: ensures the models dir,
    (re)creates the container with the placement's model/port/env, and
    refuses to start gguf placements whose file is missing (ship it with
    `noo cluster sync-model-files <node> -m <model>`).
    """
    body = {"model": model, "desired_state": "stopped" if stopped else "running",
            "tls": tls}
    if port is not None:
        body["port"] = port
    if image:
        body["image"] = image
    env_map = _parse_env_options(env)
    if env_map:
        body["env"] = env_map
    gateway_url = get_gateway_url()
    try:
        r = httpx.put(f"{gateway_url}/api/cluster/nodes/{node}/placements/{backend}",
                      json=body, timeout=10.0, **cli_httpx_kwargs())
        r.raise_for_status()
    except Exception as e:
        fatal(f"Failed to place: {e}")
    print_success(f"{node}: {backend} → {model} "
                  f"({'stopped' if stopped else 'running'}) — agent reconciles within 5 min")


@cluster_app.command("unplace")
def unplace_backend(
    node: str = typer.Argument(..., help="Node ID", autocompletion=_complete_node_ids),
    backend: str = typer.Argument(..., help="Backend type", autocompletion=_complete_backends),
):
    """🗑️  Remove a placement (the agent stops managing it; container is left as-is)."""
    gateway_url = get_gateway_url()
    try:
        r = httpx.delete(f"{gateway_url}/api/cluster/nodes/{node}/placements/{backend}",
                         timeout=10.0, **cli_httpx_kwargs())
        r.raise_for_status()
    except Exception as e:
        fatal(f"Failed to unplace: {e}")
    print_success(f"{node}: {backend} placement removed")










# Cluster-shared env vars: pushed from controller to every worker so
# backend image/model/parser tuning stays consistent. Not exhaustive —
# anything matching one of these PREFIXES is shipped, plus the explicit
# allowlist for non-prefixable vars.
#
# WHY: workers' .env files were created at provisioning time and frozen.
# When VLLM_IMAGE drifts on the controller (e.g. swapping :latest for
# :gemma4 to fix a tool-parser regression), workers keep using the old
# tag → inconsistent backend behavior across the cluster. This sync
# closes that drift the same way `_ship_compose_file` closes compose
# drift.
#
# NOT shipped (kept worker-local OR controller-only):
#   NODE_ID, NODE_IP, NODE_TIER, GPU_MODEL, VRAM_GB, GPU_MEM_UTIL → worker hardware
#   VLLM_MODEL, LLAMACPP_MODEL, OLLAMA_MODELS → per-worker model choice
#     (host8 runs E2B-it, HOST3 runs E4B-it — sharing this would OOM
#     the smaller GPU; same logic for any heterogeneous-fleet setup)
#   VLLM_QUANTIZATION, TENSOR_PARALLEL_SIZE → per-worker GPU capability
#   POSTGRES_PASSWORD, REDIS_PASSWORD, JWT_*, GOOGLE_*, TELEGRAM_* → controller-only
#   OLLAMA_DATA_DIR, MODELS_DIR, HF_CACHE_DIR → host-specific paths
#
# Curation principle: only ship what would otherwise CAUSE drift between
# nodes (image tag, parser config, TLS hints, HF auth). Per-node tuning
# stays local — that's why workers have a `.env` in the first place.
_CLUSTER_SHARED_ENV_EXACT = (
    # Image tags — closes the regression that triggered this proposal
    "VLLM_IMAGE", "VLLM2_IMAGE", "LLAMACPP_IMAGE", "OLLAMA_IMAGE", "TEI_IMAGE",
    # Tool/reasoning parser hints — must match across cluster for
    # consistent agentic loop behavior
    "VLLM_TOOL_PARSER", "VLLM_REASONING_PARSER",
    # Context window — typically uniform; if you want per-node, override
    # locally in the worker's .env after the sync (sync replaces, not
    # merges, so per-node overrides need post-sync care for now)
    "VLLM_MAX_MODEL_LEN", "VLLM_MAX_TOKENS",
    # Hugging Face auth for gated model downloads (same token everywhere)
    "HF_TOKEN",
    # Network-bind POLICY. Cluster-wide intent (tailnet|all); each
    # node resolves its own concrete IP locally (NODE_IP / tailscale). The
    # per-node NOO_BIND_ADDR is deliberately NOT shared — it's worker-specific.
    "NOO_BIND_MODE",
)
_CLUSTER_SHARED_ENV_PREFIXES: tuple[str, ...] = ()  # nothing shared by prefix anymore
_CLUSTER_SHARED_ENV_EXCLUDE = ()  # exact-match list is the allowlist; no exclusions needed










# Backends whose *_IMAGE we sync via _ship_cluster_env. After the env is
# updated, we may need to pull + force-recreate the corresponding
# container so the new tag actually runs (changing .env alone doesn't
# touch a running container — docker uses the image SHA the container
# was created from, not the :tag).
_IMAGE_KEY_TO_SERVICE = {
    "VLLM_IMAGE": ("vllm", "noo-vllm"),
    "VLLM2_IMAGE": ("vllm-secondary", "noo-vllm-secondary"),
    "LLAMACPP_IMAGE": ("llamacpp", "noo-llamacpp"),
    "OLLAMA_IMAGE": ("ollama", "noo-ollama"),
    "TEI_IMAGE": ("tei", "noo-tei"),
}








# Note: scheduler-run moved to `noo jobs run` (jobs_cli.py) — one entry point
# for scheduler jobs, `noo inference` for direct inference.






@cluster_app.command("clear-cooldowns")
def clear_cooldowns(
    node_id: Optional[str] = typer.Argument(None, help="Node ID (all nodes if omitted)"),
):
    """Clear backend auto-start cooldowns after a rebuild or restart.

    When backend auto-start fails, exponential backoff prevents immediate
    retries.  After fixing the underlying issue (rebuild, restart, etc.),
    run this to allow auto-start attempts immediately.

    Examples:
        noo cluster clear-cooldowns          # clear all
        noo cluster clear-cooldowns gpu-01   # clear for one node
    """
    gateway_url = get_gateway_url()
    try:
        params = {"node_id": node_id} if node_id else {}
        resp = httpx.post(
            f"{gateway_url}/api/cluster/backends/clear-cooldowns",
            params=params, timeout=10.0,
            **cli_httpx_kwargs(),
        )
        resp.raise_for_status()
        data = resp.json()
        cleared = data.get("cleared", 0)
        target = node_id or "all nodes"
        print_success(f"Cleared {cleared} cooldown entries for {target}.")
    except Exception as e:
        print_error(f"Failed to clear cooldowns: {e}")
