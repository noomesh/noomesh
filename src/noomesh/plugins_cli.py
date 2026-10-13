# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for plugin management.

Dev-only, trusted-code surface: Python-package plugins under
``~/.noo/plugins`` are IMPORTED in-process — no sandbox, full access to
whatever this process holds. Untrusted or third-party extension code
belongs in skills (``noo skills scaffold``), which execute in the Docker
sandbox via the node-agent.
"""
from __future__ import annotations

import os
from pathlib import Path

import typer

from .cli_utils import console, print_info, print_warning

plugins_app = typer.Typer(
    help="Manage plugins (dev-only: plugins import in-process — use skills for sandboxed extensions)",
    rich_markup_mode="rich",
)


@plugins_app.command("list")
def list_plugins() -> None:
    """List discovered and loaded plugins."""
    from .plugins import PluginManager

    print_warning(
        "Python-package plugins load IN-PROCESS (no sandbox) — dev-only, "
        "trusted code. For sandboxed extensions, write a skill: "
        "`noo skills scaffold <name>`."
    )

    plugin_dir_str = os.getenv("NOO_PLUGIN_DIR") or str(
        Path.home() / ".noo" / "plugins"
    )
    plugin_dir = Path(plugin_dir_str)

    pm = PluginManager(plugin_dir=plugin_dir)
    discovered = pm.discover_plugins()

    if not discovered:
        print_info(f"No plugins found in {plugin_dir}")
        print_info("Create a plugin directory with a plugin.py inside it to get started.")
        return

    from rich.table import Table

    table = Table(title=f"Plugins ({plugin_dir})")
    table.add_column("Name", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Version")
    table.add_column("Description")

    for name in discovered:
        plugin = pm.load_plugin(name)
        if plugin:
            meta = plugin.metadata
            table.add_row(name, "loaded", meta.version, meta.description)
        else:
            table.add_row(name, "[red]failed[/red]", "-", "-")

    console.print(table)
