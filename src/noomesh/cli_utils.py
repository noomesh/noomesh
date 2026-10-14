# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared CLI helpers for consistent output formatting across all PAI modules."""

from __future__ import annotations

import asyncio
from . import json_fast as _json
import os
from typing import Any

import typer
from rich.console import Console

console = Console()

# Module-level verbose flag, set by cli.py main callback
_verbose = False
# Module-level JSON output flag
_json_output = False


def set_verbose(value: bool) -> None:
    global _verbose
    _verbose = value


def is_verbose() -> bool:
    return _verbose


def set_json_output(value: bool) -> None:
    """Enable JSON output mode (suppresses Rich formatting)."""
    global _json_output
    _json_output = value


def is_json_output() -> bool:
    return _json_output


def output_json(data: Any) -> None:
    """Print data as formatted JSON to stdout. Use in --json mode."""
    typer.echo(_json.dumps(data, indent=2, default=str))


def output_result(data: Any, *, render_table=None) -> None:
    """Unified output: JSON if --json flag is set, otherwise Rich table/text.

    Args:
        data: The data to output (dict or list).
        render_table: Optional callable(data) that prints a Rich table.
            Only called when not in JSON mode.
    """
    if _json_output:
        output_json(data)
    elif render_table:
        render_table(data)
    else:
        console.print_json(data=data)


_REPO_ENV_LOADED = False


def ensure_repo_env() -> None:
    """Load the repo ``.env`` into os.environ (already-exported vars win).

    Lets ``noo`` commands read their configuration without
    the user having to ``source .env`` — which chokes on unquoted values
    anyway. Idempotent; silently skips when no .env exists.
    """
    global _REPO_ENV_LOADED
    if _REPO_ENV_LOADED:
        return
    _REPO_ENV_LOADED = True
    try:
        from pathlib import Path
        from .secrets import load_env_file
        repo_env = Path(__file__).resolve().parent.parent.parent / ".env"
        if repo_env.exists():
            load_env_file(repo_env)
    except Exception:
        pass  # best-effort — commands still work with exported env


def get_gateway_url() -> str:
    """Resolve gateway URL from env, consistent across all modules.

    Checks ``CONTROLLER_URL`` / ``NOO_GATEWAY_URL`` env vars first, then
    ``https://localhost:8080``. The gateway serves HTTPS only (it refuses to
    start without TLS material), so the old ``.env`` sniff for
    ``NOO_TLS_CERT`` — which picked ``http://`` when the key was absent —
    could only ever name a door that does not exist.
    """
    ensure_repo_env()
    # Prefer an explicit, host-reachable URL. CONTROLLER_URL is often the
    # docker-INTERNAL `gateway:8080` (useless from the host CLI); when it is,
    # fall through to NOO_GATEWAY_URL — set to the host/tailnet URL for exactly
    # this case — instead of letting the `or` shadow it and dropping to
    # localhost. (Critical once NOO_BIND_MODE=tailnet binds 8080 to the tailnet
    # IP only: localhost:8080 is then refused.)
    for candidate in (os.getenv("CONTROLLER_URL"), os.getenv("NOO_GATEWAY_URL")):
        if candidate and "://gateway:" not in candidate:
            return candidate
    return "https://localhost:8080"


def print_error(msg: str) -> None:
    """Standardized error: red X prefix."""
    console.print(f"[red]\u2717 {msg}[/red]")


def print_success(msg: str) -> None:
    """Standardized success: green checkmark prefix."""
    console.print(f"[green]\u2713 {msg}[/green]")


def print_warning(msg: str) -> None:
    """Standardized warning: yellow triangle prefix."""
    console.print(f"[yellow]\u26a0 {msg}[/yellow]")


def print_info(msg: str) -> None:
    """Informational: cyan, no prefix."""
    console.print(f"[cyan]{msg}[/cyan]")


def print_hint(msg: str) -> None:
    """Hint/tip text: dim."""
    console.print(f"[dim]{msg}[/dim]")


def fatal(msg: str) -> None:
    """Print error and exit with code 1."""
    print_error(msg)
    raise typer.Exit(1)


def http_fail(e: Exception):
    """Standardized exit for gateway HTTP failures (agent contract).

    Exit codes mirror the Rust front door (noo-cli/src/output.rs):
    3 = gateway unreachable, 4 = auth failed (401/403), 5 = gateway
    returned an error status, 1 = anything else. In ``--json`` mode the
    error is a JSON object on stderr so stdout stays data-only.
    """
    import httpx

    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        code = 4 if status in (401, 403) else 5
        kind = "auth_failed" if code == 4 else "remote_error"
        msg = f"gateway returned {status}: {e.response.text[:200]}"
    elif isinstance(e, httpx.HTTPError):
        code, kind = 3, "gateway_unreachable"
        msg = f"cannot reach gateway: {e}"
    else:
        code, kind = 1, "error"
        msg = str(e)
    if is_json_output():
        typer.echo(_json.dumps({"error": msg, "code": kind}), err=True)
    else:
        print_error(msg)
    raise typer.Exit(code)


def run_async(coro):
    """Run an async coroutine from sync code."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    if not loop.is_running():
        return loop.run_until_complete(coro)

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(asyncio.run, coro).result()


def cli_http_verify() -> bool | str:
    """Return TLS verification setting for CLI→gateway requests.

    The cluster CA path when one resolves (``NOO_TLS_CA``, else the install's
    standard location -- see ``noomesh.tls_ca``), else ``True`` (the system
    trust store). NEVER ``False``: this used to return ``False`` for an HTTPS
    gateway with no CA. A gateway whose leaf the CA issued now fails the
    handshake loudly instead of being accepted unverified. (Unlike
    ``AgentMessenger`` it does not raise on a missing CA: a CLI pointed at a
    publicly-trusted gateway needs none, and the no-login refusal in
    ``cli_httpx_kwargs`` must stay reachable without one.)
    """
    from .tls_ca import resolve_ca

    return resolve_ca() or True


def cli_client_cert() -> tuple[str, str] | None:
    """Return (cert, key) tuple for mTLS client authentication from the host CLI.

    Reads ``NOO_TLS_CERT`` and ``NOO_TLS_KEY`` environment variables.
    Returns ``None`` if not configured or files don't exist.
    """
    import os
    cert = os.environ.get("NOO_TLS_CERT", "")
    key = os.environ.get("NOO_TLS_KEY", "")
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        return (cert, key)
    return None


def rust_cli_pointer() -> str:
    """The Rust `noo` command line for the Python command now running.

    Every Python command that talks to the gateway has a native equivalent
    on the Rust `noo` under the same words (pinned by
    ``tests/test_cli_no_shared_secret.py``), so the pointer is the invoked
    path with the program name swapped. Outside a click context (a library
    caller), it is the generic form.
    """
    import click

    ctx = click.get_current_context(silent=True)
    words: list[str] = []
    while ctx is not None and ctx.parent is not None:
        if ctx.info_name:
            words.append(ctx.info_name)
        ctx = ctx.parent
    if not words:
        return "noo <the same command>"
    return "noo " + " ".join(reversed(words))


class SharedSecretRefused(SystemExit):
    """Raised instead of signing with a shared secret.

    A ``SystemExit`` on purpose: many CLI modules wrap their request in
    ``except Exception`` and would otherwise turn this refusal into a
    misleading "gateway unreachable".
    """


def cli_httpx_kwargs() -> dict:
    """Return common httpx keyword args for CLI→gateway requests.

    Includes:
    - ``verify``: TLS CA verification (only when non-default).
    - ``headers``: ``$NOO_TOKEN`` — the operator's OWN login (a per-user
      JWT, the same override the Rust CLI honours).

    There is no other credential. This used to fall back to an HMAC minted
    from ``$NOO_CLUSTER_SECRET`` as actor ``cli`` — a fleet-shared secret,
    signed by a CLI, naming nobody. That fallback is gone: with no
    ``$NOO_TOKEN`` the command REFUSES and names the Rust ``noo`` verb that
    serves the same command with the operator's login. No CLI signs with the
    cluster or controller secret (``tests/test_cli_no_shared_secret.py``).

    Usage::

        httpx.get(url, timeout=10.0, **cli_httpx_kwargs())
    """
    import os
    ensure_repo_env()
    kwargs: dict = {}
    v = cli_http_verify()
    if v is not True:  # Only set when non-default
        kwargs["verify"] = v

    jwt = os.environ.get("NOO_TOKEN", "").strip()
    if jwt:
        kwargs["headers"] = {"Authorization": f"Bearer {jwt}"}
        return kwargs

    import sys

    pointer = rust_cli_pointer()
    print(
        "error: the Python CLI no longer signs with the cluster secret, and no "
        "login was given.\n"
        f"  run: {pointer}   (the Rust noo, with your own login — `noo auth login <you>` first)",
        file=sys.stderr,
    )
    raise SharedSecretRefused(2)


def cli_async_client(timeout: float = 10.0):
    """The one right way to build a CLI→gateway httpx.AsyncClient.

    Carries TLS verification (cluster CA / self-signed), the mTLS client
    cert when configured, AND the operator's own bearer (``$NOO_TOKEN``) —
    or refuses, naming the Rust verb (see ``cli_httpx_kwargs``). Fifteen
    sub-CLI modules have now shipped clients that forgot one of these
    (silent 401s, TLS failures) — use this instead of hand-rolling:

        async with cli_async_client(timeout=30.0) as c:
            resp = await c.get(f"{get_gateway_url()}/api/...")
    """
    import httpx

    return httpx.AsyncClient(
        timeout=timeout,
        verify=cli_http_verify(),
        cert=cli_client_cert(),
        headers=cli_auth_headers(),
    )


def confirm_destructive(action: str, target: str) -> None:
    """Prompt for confirmation on destructive operations. Aborts if declined."""
    typer.confirm(f"{action} {target}?", abort=True)


def cli_auth_headers() -> dict:
    """Authorization header for CLI→gateway requests (``$NOO_TOKEN``).

    For CLIs that build their own httpx clients instead of using
    cli_httpx_kwargs — pass as AsyncClient(headers=cli_auth_headers()).
    """
    return cli_httpx_kwargs().get("headers", {})
