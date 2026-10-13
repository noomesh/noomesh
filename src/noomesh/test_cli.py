# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for the test system (noo test ...).

Provides two sub-commands:
  noo test run        — run the test suite (blocks on failure)
  noo test coverage   — run with coverage report
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from .cli_utils import console, print_error, print_info, print_success

test_app = typer.Typer(
    help="🧪 [bold]Test suite[/] — run, coverage",
    rich_markup_mode="rich",
)

# Resolve project root (directory containing pyproject.toml)
_THIS = Path(__file__).resolve()
_PROJECT_ROOT = _THIS.parent.parent.parent  # src/noomesh -> src -> project root
_TESTS_DIR = _PROJECT_ROOT / "tests"
_INTEGRATION_DIR = _TESTS_DIR / "integration"


def _find_python() -> str:
    """Return the Python executable for the current venv or system."""
    venv = os.getenv("VIRTUAL_ENV")
    if venv:
        candidate = Path(venv) / "bin" / "python"
        if candidate.exists():
            return str(candidate)
    return sys.executable


# ── noo test run ─────────────────────────────────────────────────


@test_app.command()
def run(
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output."),
    failfast: bool = typer.Option(True, "-x", "--failfast/--no-failfast", help="Stop on first failure."),
    pattern: Optional[str] = typer.Option(None, "-k", help="Only run tests matching pattern."),
    include_integration: bool = typer.Option(False, "--integration", help="Include integration tests."),
) -> None:
    """🚀 [bold]Run[/] the test suite. Exits non-zero on failure."""
    cmd = [_find_python(), "-m", "pytest"]

    if not include_integration:
        cmd.extend(["--ignore", str(_INTEGRATION_DIR)])

    if verbose:
        cmd.append("-v")
    if failfast:
        cmd.append("-x")
    if pattern:
        cmd.extend(["-k", pattern])

    cmd.append(str(_TESTS_DIR))

    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    result = subprocess.run(cmd, cwd=str(_PROJECT_ROOT))

    if result.returncode == 0:
        print_success("All tests passed.")
    else:
        print_error(f"Tests failed (exit code {result.returncode}).")
        raise typer.Exit(result.returncode)


# ── noo test coverage ────────────────────────────────────────────


@test_app.command()
def coverage(
    html: bool = typer.Option(False, "--html", help="Generate HTML coverage report."),
) -> None:
    """📊 [bold]Run tests with coverage[/] report."""
    cmd = [
        _find_python(), "-m", "pytest",
        "--ignore", str(_INTEGRATION_DIR),
        "--cov=noomesh",
        "--cov-report=term-missing",
        str(_TESTS_DIR),
    ]
    if html:
        cmd.insert(-1, "--cov-report=html")

    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    result = subprocess.run(cmd, cwd=str(_PROJECT_ROOT))

    if result.returncode == 0:
        print_success("Coverage report complete.")
        if html:
            print_info(f"HTML report at: {_PROJECT_ROOT / 'htmlcov' / 'index.html'}")
    else:
        print_error(f"Tests failed (exit code {result.returncode}).")
        raise typer.Exit(result.returncode)
