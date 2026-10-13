# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The CLI sub-app registrations are try/except-guarded — a renamed or
missing module fails SILENTLY and the command just vanishes (exactly how
`noo stack start --dist` fell through to a typer error during the noomesh
cutover: cli.py imported .mesh_cli while the file was still metis_cli.py).
Pin the sub-apps that must exist."""

from typer.main import get_command

from noomesh.cli import app


def test_core_subapps_registered():
    cmd = get_command(app)
    names = set(cmd.commands.keys())
    for required in ("stack", "rag", "recall", "cluster", "security", "heartbeat"):
        assert required in names, f"sub-app '{required}' failed to register (silent ImportError?)"
