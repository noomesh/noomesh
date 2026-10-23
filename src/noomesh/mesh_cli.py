# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI subcommands for Docker service management (noo stack ...)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import typer

from . import json_fast as _json
from .cli_utils import confirm_destructive, is_json_output, output_json, print_error

mesh_app = typer.Typer(
    add_completion=False,
    help="🐳 [dim]Docker service management[/]",
    rich_markup_mode="rich",
)

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"


def _err(msg: str, *, code: str = "error") -> None:
    """Error message: JSON on stderr in --json mode, Rich otherwise."""
    if is_json_output():
        typer.echo(_json.dumps({"error": msg, "code": code}), err=True)
    else:
        print_error(msg)


def _run_script(
    name: str,
    args: list[str] | None = None,
    *,
    json_action: str | None = None,
) -> None:
    """Run a bash script from the scripts directory, passing through args.

    In --json mode, when ``json_action`` is given, the script's stdout is
    redirected to stderr (stdout stays data-only) and a
    ``{"status": "ok", "action": ...}`` object is emitted on success.
    A failed script always exits with its return code (or 1), never 0.
    """
    script = SCRIPTS_DIR / name
    if not script.exists():
        _err(f"Script not found: {script}")
        raise typer.Exit(1)

    cmd = ["bash", str(script)]
    if args:
        cmd.extend(args)

    if is_json_output() and json_action:
        result = subprocess.run(cmd, stdout=sys.stderr)
        if result.returncode == 0:
            output_json({"status": "ok", "action": json_action})
            raise typer.Exit(0)
        _err(f"{name} exited with {result.returncode}", code="subprocess_failed")
        raise typer.Exit(result.returncode or 1)

    result = subprocess.run(cmd)
    raise typer.Exit(result.returncode)


# install-watcher is NATIVE ONLY (noo-cli commands/mesh.rs, WP-B2) — the
# Python version and its impl (onboard/watcher_install.py) were removed
# on 2026-08-06 with the rest of the Python wizard (history in git log before that).


@mesh_app.command()
def start(
    profile: Optional[str] = typer.Option(None, "--profile", help="Docker Compose profile to activate."),
    pull: bool = typer.Option(False, "--pull", help="Pull latest images before starting."),
    build: bool = typer.Option(False, "--build", help="Build custom images before starting."),
    dist: bool = typer.Option(False, "--dist", help="Run the published GHCR images instead of building from local source."),
    tag: Optional[str] = typer.Option(None, "--tag", help="Release tag for --dist (default: newest stack-v* tag)."),
) -> None:
    """Start Docker services.

    By default the first-party images are BUILT from the local source tree
    (the base compose file pins pull_policy=build), so the running stack
    always reflects your working copy.

    org's GHCR — the same artifacts a customer would install. Nothing
    org's private GHCR — the same artifacts a customer would install. Nothing
    is compiled; the source tree is ignored. Use it to verify a release
    actually works end to end. Flip back with a plain 'noo stack start'.

    Requires 'docker login ghcr.io' with a read:packages PAT.
    """
    if build and dist:
        _err("--build and --dist are mutually exclusive (--dist never compiles).")
        raise typer.Exit(1)
    if tag and not dist:
        _err("--tag only applies with --dist.")
        raise typer.Exit(1)

    args: list[str] = []
    if profile:
        args.extend(["--profile", profile])
    if pull:
        args.append("--pull")
    if build:
        args.append("--build")
    if dist:
        args.append("--dist")
    if tag:
        args.extend(["--tag", tag])
    _run_script("noomesh-start.sh", args, json_action="start")


@mesh_app.command()
def stop(
    volumes: bool = typer.Option(False, "--volumes", "-v", help="Remove volumes when stopping."),
) -> None:
    """Stop Docker services."""
    args: list[str] = []
    if volumes:
        args.append("-v")
    _run_script("noomesh-stop.sh", args, json_action="stop")


@mesh_app.command()
def rebuild(
    profile: Optional[str] = typer.Option(None, "--profile", help="Docker Compose profile to activate."),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick restart only (no Docker build). Picks up Python source changes via volume mount."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Force full rebuild without Docker layer cache."),
    gateway_engine: Optional[str] = typer.Option(None, "--gateway-engine", help="Gateway engine: rust (default) or python."),
    node_engine: Optional[str] = typer.Option(None, "--node-engine", help="Node agent engine: go (default) or python."),
    background: bool = typer.Option(False, "--background", "-b", help="Queue the rebuild through noo-hostd and return immediately. Follow with 'noo stack rebuild-status'."),
    services: Optional[List[str]] = typer.Argument(None, help="Service names to rebuild."),
) -> None:
    """Rebuild Docker services.

    Defaults: Rust gateway + Go node-agent. Use --gateway-engine=python
    or --node-engine=python to fall back to the Python implementations.
    With --background the rebuild runs detached under noo-hostd —
    the terminal is free immediately and progress is visible via
    'noo stack rebuild-status' and the dashboard operations panel.
    """
    if background:
        # The watcher's detached job runs with the watcher's environment,
        # so env-var overrides set here would silently not apply.
        if gateway_engine or node_engine or profile:
            _err(
                "--gateway-engine/--node-engine/--profile need a foreground "
                "run (they work via environment variables the detached host "
                "watcher job doesn't inherit)."
            )
            raise typer.Exit(1)
        _queue_background_rebuild(quick=quick, no_cache=no_cache, services=services or [])
        return

    if gateway_engine:
        os.environ["GATEWAY_ENGINE"] = gateway_engine
    if node_engine:
        os.environ["NODE_ENGINE"] = node_engine

    args: list[str] = []
    if quick:
        args.append("--quick")
    if no_cache:
        args.append("--no-cache")
    if profile:
        args.extend(["--profile", profile])
    if services:
        args.extend(services)
    _run_script("noomesh-rebuild.sh", args, json_action="rebuild")


def _host_spool_dir() -> Path:
    """Host side of the ./.noo-host-spool bind mount (repo root)."""
    return SCRIPTS_DIR.parent / ".noo-host-spool"


def _queue_background_rebuild(*, quick: bool, no_cache: bool, services: list[str]) -> None:
    from .gateway.host_spool import write_command

    # Same probe the Rust CLI uses: the spool executor is noo-hostd (a user
    # unit). The bash host watcher it replaced is retired.
    probe = subprocess.run(
        ["systemctl", "--user", "is-active", "--quiet", "noo-hostd"],
        capture_output=True,
    )
    if probe.returncode != 0:
        _err(
            "noo-hostd is not running — nothing would pick the rebuild "
            "up. Install or restart it with: noo onboard --only services"
        )
        raise typer.Exit(1)

    args: list[str] = []
    if quick:
        args.append("--quick")
    if no_cache:
        args.append("--no-cache")
    args.extend(services)

    path = write_command(
        "stack-rebuild", "stack",
        args=args,
        requested_by="cli:mesh_rebuild",
        spool_dir=str(_host_spool_dir()),
    )
    if not path:
        _err("Could not write the spool command (see log output above).")
        raise typer.Exit(1)
    if is_json_output():
        output_json(
            {"status": "ok", "action": "rebuild-queued", "command": Path(path).name}
        )
        return
    typer.echo(f"✓ Rebuild queued through noo-hostd ({Path(path).name}).")
    typer.echo("  Follow progress:  noo stack rebuild-status [--follow]")
    typer.echo("  Dashboard:        Self-Regulation → Host Operations")


@mesh_app.command("rebuild-status")
def rebuild_status(
    follow: bool = typer.Option(False, "--follow", "-f", help="Tail the rebuild log live."),
) -> None:
    """Show the status of the most recent background stack rebuild."""
    import json

    spool = _host_spool_dir()
    latest_name, latest = None, None
    for f in sorted(spool.glob("*.result.json"), reverse=True):
        try:
            data = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if data.get("op") == "stack-rebuild":
            latest_name = f.name.removesuffix(".result.json")
            latest = data
            break
    if latest is None:
        if is_json_output():
            output_json({"rebuild": None})
        else:
            typer.echo("No background rebuild found. Start one with: noo stack rebuild -b")
        raise typer.Exit(0)

    status = latest.get("status", "done")
    if status == "done" and not latest.get("ok", False):
        status = "failed"

    log_path = spool / f"{latest_name}.rebuild.log"

    if is_json_output():
        payload = dict(latest)
        payload["name"] = latest_name
        payload["status"] = status
        if log_path.exists():
            payload["log_tail"] = log_path.read_text(errors="replace").splitlines()[-15:]
        output_json(payload)
        return

    icon = {"running": "⏳", "done": "✓", "failed": "✗"}.get(status, "?")
    typer.echo(f"{icon} stack-rebuild [{status}]  at={latest.get('ts', '?')}  rc={latest.get('rc')}")
    if latest.get("stderr"):
        typer.echo(f"  {latest['stderr']}")

    if not log_path.exists():
        return
    if follow and status == "running":
        typer.echo(f"--- tailing {log_path} (Ctrl-C to stop) ---")
        subprocess.run(["tail", "-f", str(log_path)])
    else:
        lines = log_path.read_text(errors="replace").splitlines()[-15:]
        if lines:
            typer.echo(f"--- last {len(lines)} log lines ---")
            for line in lines:
                typer.echo(f"  {line}")


@mesh_app.command()
def logs(
    follow: bool = typer.Option(False, "--follow", "-f", help="Follow log output."),
    services: Optional[List[str]] = typer.Argument(None, help="Service names to show logs for."),
) -> None:
    """Show logs for Docker services."""
    args: list[str] = []
    if follow:
        args.append("-f")
    if services:
        args.extend(services)
    _run_script("noomesh-logs.sh", args)


@mesh_app.command()
def restart(
    profile: Optional[str] = typer.Option(None, "--profile", help="Docker Compose profile to activate."),
    services: Optional[List[str]] = typer.Argument(None, help="Service names to restart."),
) -> None:
    """Restart Docker services."""
    args: list[str] = []
    if profile:
        args.extend(["--profile", profile])
    if services:
        args.extend(services)
    _run_script("noomesh-restart.sh", args, json_action="restart")


@mesh_app.command()
def status() -> None:
    """Show status of Docker services."""
    if is_json_output():
        _status_json()
        return
    _run_script("noomesh-status.sh")


def _status_json() -> None:
    """Structured container state for --json mode (docker ps, noo-* containers)."""
    try:
        proc = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=noo-", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        _err("docker not found on PATH", code="subprocess_failed")
        raise typer.Exit(1)
    if proc.returncode != 0:
        _err(proc.stderr.strip() or "docker ps failed", code="subprocess_failed")
        raise typer.Exit(proc.returncode or 1)
    containers = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            c = _json.loads(line)
        except ValueError:
            continue
        containers.append(
            {
                "name": c.get("Names", ""),
                "image": c.get("Image", ""),
                "state": c.get("State", ""),
                "status": c.get("Status", ""),
                "ports": c.get("Ports", ""),
            }
        )
    output_json({"containers": containers, "count": len(containers)})


@mesh_app.command()
def clean(
    volumes: bool = typer.Option(False, "--volumes", "-v", help="Also remove volumes."),
    images: bool = typer.Option(False, "--images", help="Also remove custom images."),
    all_: bool = typer.Option(False, "--all", help="Remove volumes, images, and caches."),
    deep: bool = typer.Option(False, "--deep", help="All of --all plus unused upstream images."),
    cache: bool = typer.Option(False, "--cache", help="Prune Docker build cache."),
    hf_cache: bool = typer.Option(False, "--hf-cache", help="Remove Windows HuggingFace cache."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Stop ALL containers across all profiles and clean up orphans."""
    if not yes and (all_ or deep or volumes):
        confirm_destructive("Clean all Docker resources on", "this host")

    args: list[str] = []
    if deep:
        args.append("--deep")
    elif all_:
        args.append("--all")
    else:
        if volumes:
            args.append("-v")
        if images:
            args.append("--images")
        if cache:
            args.append("--cache")
        if hf_cache:
            args.append("--hf-cache")
    if yes:
        # Also auto-confirm the script's own per-resource prompts (postgres /
        # redis volumes, PKI, secrets) — otherwise -y stops at the Python
        # confirm and the run still blocks on stdin.
        args.append("--yes")
    _run_script("noomesh-clean.sh", args, json_action="clean")


@mesh_app.command()
def reset(
    dist: bool = typer.Option(False, "--dist", help="Stand back up from the published GHCR images (distribution install)."),
    tag: Optional[str] = typer.Option(None, "--tag", help="Release tag for --dist (default: newest stack-v* tag)."),
    ci: bool = typer.Option(False, "--ci", help="Run onboarding non-interactively (accept defaults)."),
    keep_env: bool = typer.Option(False, "--keep-env", help="Preserve .env across the wipe (NOT a true zero-to-one test)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Tear this box down and stand it back up from scratch.

    Runs the full first-install path: deep clean (volumes, images, PKI,
    secrets, CA trust) → onboarding wizard → service start. Use it to verify
    the zero-to-one experience a new user gets.

    With --dist the rebuilt stack runs the published GHCR images, so you are
    testing the actual distribution artifacts rather than a local build.

    DESTRUCTIVE: deletes all conversations, documents, embeddings and
    certificates on this host.
    """
    if tag and not dist:
        _err("--tag only applies with --dist.")
        raise typer.Exit(1)

    args: list[str] = []
    if dist:
        args.append("--dist")
    if tag:
        args.extend(["--tag", tag])
    if ci:
        args.append("--ci")
    if keep_env:
        args.append("--keep-env")
    if yes:
        args.append("--yes")
    _run_script("noomesh-reset.sh", args, json_action="reset")


@mesh_app.command()
def ollama(
    args: Optional[List[str]] = typer.Argument(None, help="Arguments to pass to ollama (e.g. list, rm qwen2.5:14b, pull qwen3:8b)."),
    container: str = typer.Option("noo-ollama", "--container", "-c", help="Ollama container name."),
) -> None:
    """Run ollama commands inside the Docker container.

    Examples:
        stack ollama list
        stack ollama rm qwen2.5-coder:14b
        stack ollama pull qwen3:8b
        stack ollama ps
        stack ollama show qwen3:8b
    """
    cmd = ["docker", "exec", container, "ollama"]
    if args:
        cmd.extend(args)
    else:
        cmd.append("list")  # default to list

    result = subprocess.run(cmd)
    raise typer.Exit(result.returncode)
