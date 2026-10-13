# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from .cli_utils import (
    console,
    ensure_repo_env,
    print_error,
    set_json_output,
    set_verbose,
)


def version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import PackageNotFoundError, version
        try:
            v = version("noomesh")
        except PackageNotFoundError:
            v = "unknown"
        console.print(f"Mesh {v}")
        raise typer.Exit()


app = typer.Typer(
    add_completion=False,
    help="[bold cyan]Mesh[/] - Local-first AI agent cluster",
    rich_markup_mode="rich",
)
# Panel names for command grouping
PANEL_CORE = "Core"
PANEL_CLUSTER = "Cluster"
PANEL_INFRA = "Infrastructure"

mcp_app = typer.Typer(help="🔌 [dim]MCP server management[/]", rich_markup_mode="rich")
app.add_typer(mcp_app, name="mcp", rich_help_panel=PANEL_INFRA)


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=version_callback, is_eager=True,
        help="Show version and exit."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show detailed output.",
    ),
    json_out: bool = typer.Option(
        False, "--json",
        help="Output as machine-readable JSON.",
    ),
) -> None:
    """Mesh - cluster-first AI agent system."""
    set_verbose(verbose)
    set_json_output(json_out)
    # Single bootstrap point for CLI context: load the repo .env (exported
    # env still wins) so EVERY subcommand sees secrets/config uniformly.
    # Retires the per-module whack-a-mole (cluster 401s, pki falling back
    # to ~/.config/mesh/pki, user-list needing DATABASE_URL exported).
    ensure_repo_env()


# Add cluster management commands
try:
    from .cluster.cli import cluster_app
    app.add_typer(cluster_app, name="cluster", rich_help_panel=PANEL_CLUSTER)
except ImportError:
    pass

# Add models management commands
try:
    from .cluster.models_cli import models_app
    app.add_typer(models_app, name="models", rich_help_panel=PANEL_CLUSTER)
except ImportError:
    pass

# Add cluster tools management commands
try:
    from .cluster.tools_cli import tools_app
    app.add_typer(
        tools_app, name="tools",
        help="🔧 Manage [bold]cluster tools[/]",
        rich_help_panel=PANEL_CLUSTER,
    )
except ImportError:
    pass

# Add mesh (Docker service management) commands
try:
    from .mesh_cli import mesh_app
    app.add_typer(
        mesh_app, name="stack",
        help="🐳 [dim]Docker service management[/]",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Add memory management commands
try:
    from .memory_cli import memory_app
    app.add_typer(
        memory_app, name="memory",
        help="🧠 [dim]Memory & embedding management[/]",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Add RAG commands
try:
    from .rag_cli import rag_app
    app.add_typer(
        rag_app, name="rag",
        help="[bold green]PageIndex RAG[/bold green] commands",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Add autonomy commands
try:
    from .autonomy_cli import autonomy_app
    app.add_typer(
        autonomy_app, name="autonomy",
        help="[bold magenta]Autonomy engine[/bold magenta] monitoring & control",
        rich_help_panel=PANEL_CLUSTER,
    )
except ImportError:
    pass

# Add multi-agent collaboration commands
try:
    from .agents_cli import agents_app
    app.add_typer(
        agents_app, name="agents",
        help="[bold cyan]Multi-agent[/bold cyan] collaboration",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass

# Add workflow automation commands
try:
    from .workflow_cli import workflow_app
    app.add_typer(
        workflow_app, name="workflow",
        help="[bold yellow]Workflow[/bold yellow] automation",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass

# Add skill management commands
try:
    from .skills_cli import skills_app
    app.add_typer(
        skills_app, name="skills",
        help="[bold green]Containerized skills[/] — list, info, run",
        rich_help_panel=PANEL_CLUSTER,
    )
except ImportError:
    pass

# Add browser automation commands
try:
    from .browser_cli import browser_app
    app.add_typer(
        browser_app, name="browser",
        help="[bold]Browser automation[/] — status, open, stop",
        rich_help_panel=PANEL_CLUSTER,
    )
except ImportError:
    pass

# Add plugin management commands
try:
    from .plugins_cli import plugins_app
    app.add_typer(
        plugins_app, name="plugins",
        help="[dim]Plugin management[/]",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Add test suite management commands
try:
    from .test_cli import test_app
    app.add_typer(
        test_app, name="test",
        help="🧪 [bold]Test suite[/] — run, generate, accept",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Add voice commands
try:
    from .voice_cli import voice_app
    app.add_typer(voice_app, name="voice", rich_help_panel=PANEL_CORE)
except ImportError:
    pass

# Add channel adapter commands
try:
    from .channels_cli import channels_app
    app.add_typer(
        channels_app, name="channels",
        help="[bold blue]Channel adapters[/bold blue] (WhatsApp, Google Chat)",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass

# Add proactive agent commands
try:
    from .proactive_cli import proactive_app
    app.add_typer(
        proactive_app, name="proactive",
        help="[bold green]Proactive agent[/bold green] loop -- alerts & notifications",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass

# Add recall memory commands
try:
    from .recall_cli import recall_app
    app.add_typer(
        recall_app, name="recall",
        help="[bold]Episodic recall[/] (System 1 memory)",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Add log aggregation commands
try:
    from .log_cli import logs_app
    app.add_typer(
        logs_app, name="logs",
        help="[dim]Log aggregation[/]",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Command groups an installed add-on declares (``cli_groups`` extensions, see
# ``noomesh.addon_roles``): each is a Typer app registered under its declared
# name. With no add-on declaring any, nothing is added.
from .addon_roles import CLI_GROUPS, extensions as _addon_extensions

for _group_name, _group_app in _addon_extensions(CLI_GROUPS):
    app.add_typer(
        _group_app, name=_group_name,
        help=getattr(getattr(_group_app, "info", None), "help", None),
        rich_help_panel=PANEL_CORE,
    )

# Add Heartbeat cron scheduler commands
try:
    from .heartbeat_cli import heartbeat_app
    app.add_typer(
        heartbeat_app, name="heartbeat",
        help="[dim]Heartbeat cron scheduler[/] for automated tasks",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# The onboarding wizard is native Rust only (noo-cli/src/onboard/ — plain,
# --tui and --web frontends). The Python wizard was archived to
# legacy/python-onboard/ on 2026-08-06; registering a second, divergent
# implementation here is how a critical fix (tailscale cert SANs) once
# shipped as dead code. `noo onboard` never reaches this CLI.

# Add chat commands
try:
    from .chat_cli import chat_app
    app.add_typer(
        chat_app, name="chat",
        help="💬 [bold]Interactive chat[/] with the cluster",
        rich_help_panel=PANEL_CORE,
        invoke_without_command=True,
    )
except ImportError:
    pass

# Add database migration commands
try:
    from .db.db_cli import db_app
    app.add_typer(
        db_app, name="db",
        help="[dim]Schema migrations[/] (mesh: gateway native runner; memory: alembic in trellion)",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass


@app.command(rich_help_panel=PANEL_CORE, hidden=True)
def tui() -> None:
    """[dim]Retired[/] — use the web dashboard or `noo chat`."""
    # Retired 2026-08-16: the web dashboard (noo-mesh-ui-web, served by the
    # gateway) is the interactive UI and `noo chat` covers the terminal. The
    # module is archived at legacy/python-tui-reference/. The Rust front door
    # answers `noo tui` natively with the same pointer; this stub is only for
    # direct `noo-py tui` invocations.
    print_error("`noo tui` is retired — use the web dashboard or `noo chat`.")
    raise typer.Exit(2)


# Add approval queue commands
try:
    from .approval_cli import approval_app
    app.add_typer(
        approval_app, name="approval",
        help="[bold]Approval queue[/] — review pending tool-execution requests",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass

# Add job & scheduler management commands
try:
    from .jobs_cli import jobs_app
    app.add_typer(
        jobs_app, name="jobs",
        help="[bold yellow]Jobs[/] & scheduler management",
        rich_help_panel=PANEL_CLUSTER,
    )
except ImportError:
    pass

# Add knowledge graph exploration commands
try:
    from .graph_cli import graph_app
    app.add_typer(
        graph_app, name="graph",
        help="[bold green]Knowledge graph[/] exploration",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass

# Add quick inference commands
try:
    from .inference_cli import inference_app
    app.add_typer(
        inference_app, name="inference",
        help="[bold]Inference[/] — run prompts on the GPU cluster",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass

# Add runtime configuration commands (replaces inline config command)
try:
    from .config_cli import config_app
    app.add_typer(
        config_app, name="config",
        help="[bold]Configuration[/] — view and update runtime config",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass

# Add prompt skills management commands
try:
    from .prompt_skills_cli import prompt_skills_app
    app.add_typer(
        prompt_skills_app, name="prompt-skills",
        help="[bold magenta]Prompt skills[/] — expertise templates for the agent",
        rich_help_panel=PANEL_CORE,
    )
except ImportError:
    pass


# Add security management commands
try:
    from .security_cli import security_app
    app.add_typer(
        security_app, name="security",
        help="[bold red]Security[/] — users, secrets, PKI, scanning",
        rich_help_panel=PANEL_INFRA,
    )
except ImportError:
    pass


@mcp_app.command("external-setup")
def mcp_external_setup(
    gateway: Optional[Path] = typer.Option(None, "--gateway", "-G", help="Gateway URL override"),
    save: bool = typer.Option(False, "--save", help="(retired)"),
) -> None:
    """RETIRED — external MCP access is a named service key, not a shared token.

    This used to mint NOO_MCP_EXTERNAL_TOKEN, which was simultaneously the
    door's on-switch and a valid credential: every caller arrived as the same
    unattributed, uncapped, unrevocable actor. The native Rust door (#420)
    resolves per-user service keys instead, and the shared-token bypass was
    removed from both doors on 2026-08-03. A token minted here would no
    longer authenticate anything.
    """
    import os

    gw_url = gateway or os.environ.get("NOO_GATEWAY_URL", "https://mesh.local:8080")
    console.print("\n[bold]MESH external MCP access — issue a named key[/bold]")
    console.print("\n[bold]1. Open the door[/bold] (DB-authoritative; restart to apply)")
    console.print("   [cyan]noo security posture set NOO_MCP_EXTERNAL_ENABLED 1[/cyan]")
    console.print("\n[bold]2. Give the consumer an account, then a key bound to it[/bold]")
    console.print("   [cyan]noo security user create alice --scope read[/cyan]")
    console.print(
        "   [cyan]noo security service-key issue alice-claude "
        "--scopes mcp --user alice --rpm 60[/cyan]"
    )
    console.print(
        "   [dim]Their tool calls run under alice's OWN scopes and KB roles. "
        "A key with no --user is refused (403), not downgraded to operator.[/dim]"
    )
    console.print("\n[bold]3. Point the harness at the gateway door[/bold]")
    console.print(f"   [dim]{gw_url}/mcp/user[/dim]")
    console.print(
        '   [dim]headers: {"Authorization": "Bearer <the issued key>"}[/dim]'
    )
    console.print("\n[bold]4. Revoke without touching any other consumer[/bold]")
    console.print("   [cyan]noo security service-key revoke alice-claude[/cyan]")
    raise typer.Exit(2)


if __name__ == "__main__":
    app()
