# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for security management.

``noo security user list/create/set-password/disable``
``noo security generate-secret <type>``
``noo security scan``
``noo security pki init/issue/issue-gateway/status/rotate``
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

import typer

from .cli_utils import console, print_error, print_hint

security_app = typer.Typer(
    help="Security management — users, secrets, PKI, scanning",
    rich_markup_mode="rich",
)

user_app = typer.Typer(help="User management")
security_app.add_typer(user_app, name="user")
team_app = typer.Typer(help="KB team registry (first-class team:* roles)")
security_app.add_typer(team_app, name="team")
org_app = typer.Typer(help="Org / tenant registry (top boundary above users + teams)")
security_app.add_typer(org_app, name="org")
posture_app = typer.Typer(help="Security posture — DB-authoritative app-tier gates (operator)")
security_app.add_typer(posture_app, name="posture")

pki_app = typer.Typer(help="PKI certificate management")
security_app.add_typer(pki_app, name="pki")

service_key_app = typer.Typer(
    help="Named service keys for external inference consumers (/api/external/*)"
)
security_app.add_typer(service_key_app, name="service-key")

# Operations an external consumer may be granted. Mirrors the gateway's
# /api/external/* scope checks (service_keys.rs / routes/external.rs).
SERVICE_KEY_SCOPES = ["chat", "embeddings", "rerank", "classify", "mcp"]


# ---------------------------------------------------------------------------
# noo security generate-secret
# ---------------------------------------------------------------------------

@security_app.command("generate-secret")
def generate_secret(
    secret_type: str = typer.Argument(
        "general",
        help="Type of secret: general, jwt, cluster, fernet",
    ),
    length: int = typer.Option(32, help="Token length (bytes of entropy)"),
) -> None:
    """Generate a cryptographically secure random secret."""
    if secret_type == "fernet":
        try:
            from cryptography.fernet import Fernet
            console.print(Fernet.generate_key().decode())
        except ImportError:
            print_error("cryptography package not installed")
            raise typer.Exit(1)
    else:
        console.print(secrets.token_urlsafe(length))


# ---------------------------------------------------------------------------
# noo security scan
# ---------------------------------------------------------------------------

@security_app.command("scan")
def security_scan() -> None:
    """Scan configuration for security issues."""
    from rich.table import Table

    issues: list[tuple[str, str, str]] = []  # (severity, check, detail)

    from .secret_env import SecretFileError, secret_or_empty

    def _secret(name: str) -> str:
        # Env, NOO_SECRET_ env, or NAME_FILE — a secret delivered as a file
        # is SET, not a finding. A file that is named but unreadable is its
        # own finding, not "unset".
        try:
            return secret_or_empty(name)
        except SecretFileError as e:
            issues.append(("CRITICAL", name, str(e)))
            return "set-but-broken"

    # JWT secret
    jwt = _secret("NOO_JWT_SECRET")
    if not jwt or jwt == "dev-secret-change-in-production":
        issues.append(("CRITICAL", "JWT Secret", "Default or unset — set NOO_JWT_SECRET"))

    # NOTE: gateway auth is always on (invariant since config-graduation
    # phase 1) — the old NOO_AUTH_ENABLED knob was removed.

    # Cluster secret
    if not _secret("NOO_CLUSTER_SECRET"):
        issues.append(("HIGH", "Cluster Secret", "Empty — set NOO_CLUSTER_SECRET"))

    # Redis password
    if not _secret("REDIS_PASSWORD"):
        issues.append(("MEDIUM", "Redis Password", "Unset — set REDIS_PASSWORD"))

    # (No NATS password check: the shared bus password was retired by
    # the design — every principal has its own, verified by digest.)

    # Node agent token
    if not _secret("NOO_NODE_AGENT_TOKEN"):
        issues.append(("HIGH", "Node Agent Token", "Unset — set NOO_NODE_AGENT_TOKEN"))

    # .env permissions (skip on NTFS/drvfs where chmod is a no-op)
    env_path = Path(".env")
    if env_path.exists():
        try:
            mode = env_path.stat().st_mode
            if mode & 0o044 and not _is_ntfs_mount(env_path):
                issues.append(("MEDIUM", ".env Permissions", f"World-readable ({oct(mode)}) — chmod 600 .env"))
        except OSError:
            pass

    # TLS
    if not os.getenv("NOO_TLS_CERT", ""):
        issues.append(("MEDIUM", "TLS", "Not configured — set NOO_TLS_CERT + NOO_TLS_KEY"))

    # PKI
    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    if not (pki_dir / "ca.crt").exists():
        issues.append(("LOW", "Cluster PKI", "No CA — run 'noo security pki init'"))

    # Print results
    if not issues:
        console.print("[bold green]No security issues found.[/]")
        return

    table = Table(title="Security Scan Results")
    table.add_column("Severity", style="bold")
    table.add_column("Check")
    table.add_column("Detail")

    severity_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}
    for sev, check, detail in sorted(issues, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x[0])):
        color = severity_colors.get(sev, "white")
        table.add_row(f"[{color}]{sev}[/]", check, detail)

    console.print(table)
    criticals = sum(1 for s, _, _ in issues if s == "CRITICAL")
    if criticals:
        print_error(f"{criticals} CRITICAL issue(s) found")


def _is_ntfs_mount(path: Path) -> bool:
    """Return True if *path* is on an NTFS/drvfs mount (WSL2) where chmod is a no-op."""
    try:
        resolved = str(path.resolve())
        with open("/proc/mounts", "r") as f:
            best_fs = ""
            best_len = 0
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mount_point = parts[1]
                    if resolved.startswith(mount_point) and len(mount_point) > best_len:
                        best_fs = parts[2]
                        best_len = len(mount_point)
        return best_fs in ("drvfs", "9p", "ntfs", "ntfs3")
    except OSError:
        return False


# ---------------------------------------------------------------------------
# noo security user list/create/set-password/disable
#
# All user/role/proposal/service-key operations go through the gateway
# (/api/security/*, native Rust SQL handlers in routes/users.rs). The CLI
# used to open its own SQLAlchemy engine and mutate the tables in-process —
# that logic now has one audited home; the CLI is a thin caller.
# ---------------------------------------------------------------------------

def _api(method: str, path: str, body: dict | None = None) -> dict:
    """Gateway request with the CLI agent contract (http_fail exit codes)."""
    import httpx

    from .cli_utils import (
        cli_auth_headers, cli_client_cert, cli_http_verify, get_gateway_url,
        http_fail,
    )

    try:
        with httpx.Client(timeout=15.0, verify=cli_http_verify(),
                          cert=cli_client_cert(), headers=cli_auth_headers()) as c:
            resp = c.request(method, f"{get_gateway_url()}{path}", json=body)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
    except Exception as e:
        http_fail(e)


@user_app.command("list")
def user_list() -> None:
    """List all users."""
    from .cli_utils import output_result

    data = _api("GET", "/api/security/users")

    def _render(d: dict) -> None:
        from rich.table import Table

        users = d.get("users", [])
        if not users:
            console.print("[dim]No users found. Create one with: noo security user create <username>[/]")
            return
        table = Table(title="Users")
        for col in ("Username", "Disabled", "Scopes", "Created", "Last Login", "Failed Logins"):
            table.add_column(col)
        for u in users:
            table.add_row(
                u.get("username", ""),
                str(u.get("disabled")),
                str(u.get("scopes")),
                str(u.get("created_at") or "")[:19],
                str(u.get("last_login_at") or "never")[:19],
                str(u.get("failed_login_count", 0)),
            )
        console.print(table)

    output_result(data, render_table=_render)


@user_app.command("create")
def user_create(
    username: str = typer.Argument(..., help="Username"),
    scope: list[str] = typer.Option(["read", "write"], help="Scopes to assign"),
    password_stdin: bool = typer.Option(
        False, "--password-stdin",
        help="Read the password from stdin (one line, no confirm prompt) — "
             "for scripts and agent callers."),
) -> None:
    """Create a new user (prompts for password unless --password-stdin)."""
    import getpass
    import sys

    from .cli_utils import is_json_output, output_json

    if password_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if len(password) < 8:
            print_error("Password must be at least 8 characters")
            raise typer.Exit(1)
    else:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print_error("Passwords do not match")
            raise typer.Exit(1)

    data = _api("POST", "/api/security/users",
                {"username": username, "password": password, "scopes": scope})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]User '{username}' created with scopes: {scope}[/]")


@user_app.command("grant-role")
def user_grant_role(
    username: str = typer.Argument(..., help="Username"),
    role: list[str] = typer.Option(..., "--role", "-r", help="KB role(s) to grant, e.g. team:research"),
) -> None:
    """Grant extra KB roles to a user (adds to user:<name>/company/system defaults).

    This is where teams and orgs attach to users: grant team:research and
    every KB query by that user includes it. Stored in noo_kb_role_grants
    (DB-backed, editable) — takes effect within ~30s (worker cache).
    """
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/users/{username}/roles", {"roles": role})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]{username} KB roles: {data.get('roles')}[/]")


@user_app.command("revoke-role")
def user_revoke_role(
    username: str = typer.Argument(..., help="Username"),
    role: list[str] = typer.Option(..., "--role", "-r", help="KB role(s) to revoke"),
) -> None:
    """Revoke extra KB roles from a user (defaults are not revocable here)."""
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/users/{username}/roles/revoke", {"roles": role})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]{username} KB roles: {data.get('roles') or '(defaults only)'}[/]")


@user_app.command("list-roles")
def user_list_roles() -> None:
    """List all users' extra KB role grants."""
    from .cli_utils import output_result

    data = _api("GET", "/api/security/role-grants")

    def _render(d: dict) -> None:
        from rich.table import Table

        grants = d.get("grants", [])
        if not grants:
            console.print("[dim]No extra grants — everyone has their defaults "
                          "(user:<name>, company, system; operators unrestricted).[/]")
            return
        table = Table(title="KB Role Grants (extra, beyond defaults)")
        for col in ("Username", "Extra Roles", "Updated", "By"):
            table.add_column(col)
        for gr in grants:
            table.add_row(
                gr.get("username", ""),
                ", ".join(gr.get("roles") or []),
                str(gr.get("updated_at") or "")[:19],
                gr.get("updated_by") or "",
            )
        console.print(table)

    output_result(data, render_table=_render)


@user_app.command("link")
def user_link(
    username: str = typer.Argument(..., help="Canonical username to link to"),
    channel: str = typer.Argument(..., help="Channel: telegram | google_chat | whatsapp"),
    channel_user_id: str = typer.Argument(
        ..., help="The opaque per-channel sender id (Telegram chat_id, Google "
                  "Chat 'users/123', WhatsApp phone number)"),
    display_name: str = typer.Option(None, "--name", help="Optional display name for the link"),
) -> None:
    """Map a channel sender id → a canonical user.

    Once linked, inbound messages from that sender are scoped to the same
    identity as the user's terminal/CLI session. Link every channel sender
    on a multi-account install: an unlinked sender has no resolvable scope,
    so its memory/KB reads fail closed. Idempotent — re-linking updates the
    target.
    """
    from .cli_utils import is_json_output, output_json

    payload = {"channel": channel, "channel_user_id": channel_user_id}
    if display_name:
        payload["display_name"] = display_name
    data = _api("POST", f"/api/security/users/{username}/links", payload)
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Linked {channel}/{channel_user_id} → {username}[/]")


@user_app.command("unlink")
def user_unlink(
    channel: str = typer.Argument(..., help="Channel of the link to remove"),
    channel_user_id: str = typer.Argument(..., help="The channel sender id to unlink"),
) -> None:
    """Remove a channel→user link (by channel + sender id)."""
    from .cli_utils import is_json_output, output_json

    data = _api("POST", "/api/security/channel-links/unlink",
                {"channel": channel, "channel_user_id": channel_user_id})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Unlinked {channel}/{channel_user_id}[/]")


@user_app.command("links")
def user_links(
    username: str = typer.Argument(..., help="Username whose channel links to list"),
) -> None:
    """List a user's channel identity links."""
    from .cli_utils import output_result

    data = _api("GET", f"/api/security/users/{username}/links")

    def _render(d: dict) -> None:
        from rich.table import Table

        links = d.get("links", [])
        if not links:
            console.print(f"[dim]No channel links for '{d.get('username', username)}'. "
                          "Add one with: noo security user link <username> <channel> <id>[/]")
            return
        table = Table(title=f"Channel Links — {d.get('username', username)}")
        for col in ("Channel", "Channel User ID", "Display Name", "Linked"):
            table.add_column(col)
        for ln in links:
            table.add_row(
                ln.get("channel", ""),
                ln.get("channel_user_id", ""),
                ln.get("display_name") or "",
                str(ln.get("linked_at") or "")[:19],
            )
        console.print(table)

    output_result(data, render_table=_render)


@user_app.command("set-password")
def user_set_password(
    username: str = typer.Argument(..., help="Username"),
) -> None:
    """Change a user's password."""
    import getpass

    from .cli_utils import is_json_output, output_json

    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print_error("Passwords do not match")
        raise typer.Exit(1)

    data = _api("PUT", f"/api/security/users/{username}/password",
                {"password": password})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Password updated for '{username}'[/]")


# ---------------------------------------------------------------------------
# noo security team list/create/delete — KB team registry
#
# These go through the gateway API (not direct DB): the worker owns the
# registry logic — validation, member-stripping on delete, audit — and
# the CLI should not fork it.
# ---------------------------------------------------------------------------

def _team_api(method: str, path: str, body: dict | None = None) -> dict:
    import httpx

    from .cli_utils import (
        cli_auth_headers, cli_client_cert, cli_http_verify, get_gateway_url,
    )
    with httpx.Client(timeout=15.0, verify=cli_http_verify(),
                      cert=cli_client_cert(), headers=cli_auth_headers()) as c:
        resp = c.request(method, f"{get_gateway_url()}{path}", json=body)
        data = resp.json() if resp.content else {}
        if resp.status_code >= 400 or (isinstance(data, dict) and data.get("error")):
            print_error(str(data.get("error") or data.get("detail") or f"HTTP {resp.status_code}"))
            raise typer.Exit(1)
        return data


@team_app.command("list")
def team_list() -> None:
    """List registered teams with members and document counts."""
    from rich.table import Table

    teams = _team_api("GET", "/api/kb/teams").get("teams", [])
    if not teams:
        console.print("[dim]No teams registered. Create one with: "
                      "noo security team create <name>[/]")
        return
    table = Table(title="KB Teams")
    for col in ("Team", "Role", "Members", "Docs", "Description"):
        table.add_column(col)
    for t in teams:
        table.add_row(t["name"], f"team:{t['name']}",
                      ", ".join(t.get("members", [])) or "—",
                      str(t.get("doc_count", 0)), t.get("description") or "")
    console.print(table)


@team_app.command("create")
def team_create(
    name: str = typer.Argument(..., help="Team name (lowercase, e.g. research)"),
    description: Optional[str] = typer.Option(None, "--description", "-d"),
) -> None:
    """Register a team, making team:<name> a valid KB role."""
    data = _team_api("POST", "/api/kb/teams/create",
                     {"name": name, "description": description})
    console.print(f"[green]Team '{data['name']}' created — grant with: "
                  f"noo security user grant-role <user> -r {data['role']}[/]")


@team_app.command("delete")
def team_delete(
    name: str = typer.Argument(..., help="Team name"),
    force: bool = typer.Option(False, "--force",
                               help="Delete even with members/documents; "
                                    "strips the role from all grants."),
) -> None:
    """Delete a team (refuses while it has members or documents unless --force)."""
    data = _team_api("POST", "/api/kb/teams/delete", {"name": name, "force": force})
    console.print(f"[yellow]Team '{data['deleted']}' deleted "
                  f"({data['members_stripped']} grant(s) stripped, "
                  f"{data['docs_orphaned']} doc(s) keep an inert tag)[/]")


@team_app.command("link-space")
def team_link_space(
    team: str = typer.Argument(..., help="Team name"),
    channel: str = typer.Argument(..., help="Channel: google_chat | telegram | whatsapp"),
    space_id: str = typer.Argument(..., help="The space/group id (e.g. Google Chat 'spaces/AAQA…')"),
) -> None:
    """Register a channel space as a shared TEAM context (PR5c).

    Messages in that space become shared team memory (owned by team:<team>) so
    every team member — anyone granted the team:<team> role — sees the space's
    conversations. DMs stay per-individual. Idempotent.
    """
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/teams/{team}/spaces",
                {"channel": channel, "space_id": space_id})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Linked {channel} space '{space_id}' → team '{team}' (shared)[/]")


@team_app.command("unlink-space")
def team_unlink_space(
    channel: str = typer.Argument(..., help="Channel of the space link"),
    space_id: str = typer.Argument(..., help="Space id to unlink"),
) -> None:
    """Remove a space→team link (the space reverts to per-individual)."""
    from .cli_utils import is_json_output, output_json

    data = _api("POST", "/api/security/channel-team-links/unlink",
                {"channel": channel, "space_id": space_id})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Unlinked {channel} space '{space_id}'[/]")


@team_app.command("spaces")
def team_spaces(
    team: str = typer.Argument(..., help="Team whose linked spaces to list"),
) -> None:
    """List the channel spaces shared with a team."""
    from .cli_utils import output_result

    data = _api("GET", f"/api/security/teams/{team}/spaces")

    def _render(d: dict) -> None:
        from rich.table import Table

        spaces = d.get("spaces", [])
        if not spaces:
            console.print(f"[dim]No spaces linked to team '{team}'. "
                          "Add one with: noo security team link-space <team> <channel> <space_id>[/]")
            return
        table = Table(title=f"Team Spaces — {team}")
        for col in ("Channel", "Space ID", "Linked"):
            table.add_column(col)
        for s in spaces:
            table.add_row(s.get("channel", ""), s.get("space_id", ""),
                          str(s.get("created_at") or "")[:19])
        console.print(table)

    output_result(data, render_table=_render)


# ---------------------------------------------------------------------------
# noo security org — the top tenant boundary (PR5). Orgs group users + teams
# into isolation domains; a single-org deployment has just `default`.
# ---------------------------------------------------------------------------

@org_app.command("list")
def org_list() -> None:
    """List orgs (with member counts)."""
    from .cli_utils import output_result

    data = _api("GET", "/api/security/orgs")

    def _render(d: dict) -> None:
        from rich.table import Table

        orgs = d.get("orgs", [])
        if not orgs:
            console.print("[dim]No orgs. Create one with: noo security org create <id>[/]")
            return
        table = Table(title="Orgs")
        for col in ("ID", "Name", "Members", "Description"):
            table.add_column(col)
        for o in orgs:
            table.add_row(o.get("id", ""), o.get("name", ""),
                          str(o.get("members", 0)), o.get("description") or "")
        console.print(table)

    output_result(data, render_table=_render)


@org_app.command("create")
def org_create(
    org_id: str = typer.Argument(..., help="Org id (slug, e.g. acme)"),
    name: str = typer.Option(None, "--name", help="Display name (defaults to the id)"),
    description: str = typer.Option(None, "--description", "-d", help="Description"),
) -> None:
    """Create an org / tenant."""
    from .cli_utils import is_json_output, output_json

    payload = {"id": org_id}
    if name:
        payload["name"] = name
    if description:
        payload["description"] = description
    data = _api("POST", "/api/security/orgs", payload)
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Org '{org_id}' created[/]")


@user_app.command("set-org")
def user_set_org(
    username: str = typer.Argument(..., help="Username"),
    org_id: str = typer.Argument(..., help="Org id to assign the user to"),
) -> None:
    """Assign a user to an org (the org must exist)."""
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/users/{username}/org", {"org_id": org_id})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]{username} → org '{org_id}'[/]")


# ---------------------------------------------------------------------------
# noo security posture — DB-authoritative app-tier security gates (operator).
# Managed here (cluster credential), NOT from the app UI (read-only there).
# Restart-to-apply: the gates are read once at gateway boot.
# ---------------------------------------------------------------------------

@posture_app.command("list")
def posture_list() -> None:
    """Show the app-tier security posture (running vs desired, pending restart)."""
    from .cli_utils import output_result

    data = _api("GET", "/api/security/posture")

    def _render(d: dict) -> None:
        from rich.table import Table

        gates = d.get("posture", [])
        if not gates:
            console.print("[dim]No posture gates.[/]")
            return
        table = Table(title="Security Posture (app-tier)")
        for col in ("Gate", "Running", "Desired (DB)", "Source", "Pending restart"):
            table.add_column(col)
        for g in gates:
            table.add_row(
                g.get("key", ""),
                str(g.get("running") if g.get("running") is not None else "(unset)"),
                str(g.get("db_value") if g.get("db_value") is not None else "—"),
                g.get("source", ""),
                "[yellow]YES[/]" if g.get("pending_restart") else "no",
            )
        console.print(table)
        console.print("[dim]Bootstrap-tier gates (TLS, secrets) are managed via the "
                      "secrets backend, not here.[/]")

    output_result(data, render_table=_render)


@posture_app.command("set")
def posture_set(
    key: str = typer.Argument(..., help="Gate, e.g. NOO_EXEC_APPROVAL_MODE, NOO_MCP_EXTERNAL_ENABLED"),
    value: str = typer.Argument(..., help="Value (e.g. 1/0, true/false, or a mode)"),
) -> None:
    """Set an app-tier posture gate (operator-only; takes effect next restart).

    DB-authoritative: this overrides the .env default at the next gateway boot.
    The change is tamper-evident-audited. Rejected if called with an app-admin
    JWT — posture is operator-managed on purpose.
    """
    from .cli_utils import is_json_output, output_json

    data = _api("POST", "/api/security/posture", {"key": key, "value": value})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Posture {key} = {value}[/] "
                      "[yellow](restart the gateway to apply)[/]")


@posture_app.command("apply-profile")
def posture_apply_profile(
    profile: str = typer.Argument(..., help="Vetted bundle: hardened | dev"),
) -> None:
    """Apply a vetted posture bundle in one step (operator-only).

    `hardened` is the customer-distribution default (multi-user on, strict auth,
    approval-gated tools, unprivileged node-agent); `dev` is permissive local.
    Each gate takes effect on the next gateway restart.
    """
    from .cli_utils import is_json_output, output_json

    data = _api("POST", "/api/security/posture/profile", {"profile": profile})
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[green]Applied '{profile}' posture ({data.get('applied', '?')} gates)[/] "
                      "[yellow](restart the gateway to apply)[/]")


@user_app.command("disable")
def user_disable(
    username: str = typer.Argument(..., help="Username"),
) -> None:
    """Disable a user account."""
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/users/{username}/disable")
    if is_json_output():
        output_json(data)
    else:
        console.print(f"[yellow]User '{username}' disabled[/]")


@user_app.command("erase")
def user_erase(
    username: str = typer.Argument(..., help="Username to erase (right-to-be-forgotten)"),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Actually erase. Without this the command only PREVIEWS (dry-run)."),
    keep_account: bool = typer.Option(
        False, "--keep-account",
        help="Wipe the user's data but keep their noo_users login."),
) -> None:
    """Erase ALL of a user's data across every store (RTBF).

    Archive-then-delete: every matched row is snapshotted into
    noo_user_erasure_staging before deletion, all in one transaction, and the
    erasure is audited. That copy is kept for 30 days so a mistaken erase can be
    undone, then the gateway purges it automatically; after that the erase is a
    delete. Knowledge-base
    documents only the user can read are deleted; shared ones are kept with the
    user removed from their audience and pseudonymised in their provenance.
    Retained by design: the audit log, shared/NULL data, and persona-scoped
    evolution state.

    Defaults to a DRY-RUN preview — pass --yes to execute.
    """
    from .cli_utils import is_json_output, output_json, output_result

    payload = {"dry_run": not yes, "keep_account": keep_account}
    data = _api("POST", f"/api/security/users/{username}/erase", payload)

    if is_json_output():
        output_json(data)
        return

    def _render(d: dict) -> None:
        from rich.table import Table

        if d.get("dry_run"):
            plan = [p for p in d.get("plan", []) if p.get("rows", 0)]
            if not plan:
                console.print(f"[dim]Nothing to erase for '{username}'.[/]")
                return
            table = Table(title=f"DRY-RUN — would erase for '{username}'")
            table.add_column("Store")
            table.add_column("Rows", justify="right")
            for p in plan:
                table.add_row(p.get("store", ""), str(p.get("rows", 0)))
            console.print(table)
            console.print(
                f"[yellow]Total {d.get('total_rows', 0)} rows across "
                f"{len(plan)} stores. Re-run with --yes to erase.[/]")
        else:
            deleted = [p for p in d.get("deleted", []) if p.get("rows", 0)]
            total = sum(p.get("rows", 0) for p in deleted)
            console.print(
                f"[red]Erased {total} rows for '{username}'[/] "
                f"(run_id {d.get('run_id')}; a copy is kept 30 days, then purged).")

    output_result(data, render_table=_render)


# ---------------------------------------------------------------------------
# noo security user proposals/decide — the approval queue for
# agent-requested account changes
# ---------------------------------------------------------------------------

@user_app.command("proposals")
def user_proposals() -> None:
    """List user-management proposals (agent-requested account changes)."""
    from .cli_utils import output_result

    data = _api("GET", "/api/security/user-proposals")

    def _render(d: dict) -> None:
        from rich.table import Table

        proposals = d.get("proposals", [])
        if not proposals:
            console.print("[dim]No proposals. Agents file them via noo_user_propose.[/]")
            return
        table = Table(title="User-Management Proposals")
        for col in ("ID", "Status", "Action", "User", "Payload", "By", "Decided By"):
            table.add_column(col)
        for p in proposals:
            payload = p.get("payload") or {}
            status = p.get("status", "")
            colour = {"pending": "yellow", "approved": "green",
                      "denied": "red", "failed": "red"}.get(status, "")
            table.add_row(
                str(p.get("id")),
                f"[{colour}]{status}[/]" if colour else status,
                p.get("action", ""),
                str(payload.get("username", "")),
                str({k: v for k, v in payload.items() if k != "username"}),
                p.get("requested_by") or "",
                p.get("decided_by") or "",
            )
        console.print(table)
        if any(p.get("status") == "pending" for p in proposals):
            print_hint("Decide with: noo security user decide <id> --approve | --deny")

    output_result(data, render_table=_render)


@user_app.command("decide")
def user_decide(
    proposal_id: int = typer.Argument(..., help="Proposal ID"),
    approve: bool = typer.Option(False, "--approve", help="Approve and execute"),
    deny: bool = typer.Option(False, "--deny", help="Deny"),
    reason: Optional[str] = typer.Option(None, "--reason", help="Recorded with the decision"),
) -> None:
    """Approve or deny a user-management proposal (host-operator trust,
    same as direct 'noo security user' commands). Approve-create prints
    a generated password ONCE — it is not stored."""
    from .cli_utils import is_json_output, output_json

    if approve == deny:
        print_error("Pass exactly one of --approve / --deny")
        raise typer.Exit(1)

    data = _api("POST", f"/api/security/user-proposals/{proposal_id}/decide",
                {"approve": approve, "reason": reason})
    if is_json_output():
        output_json(data)
        return
    if data.get("status") == "denied":
        console.print(f"[yellow]Proposal {proposal_id} denied[/]")
        return
    console.print(f"[green]Proposal {proposal_id} approved: "
                  f"{data.get('action')} {data.get('username')}[/]")
    if pw := data.get("generated_password"):
        console.print(f"Generated password (shown once): [bold]{pw}[/]")
        print_hint("Share it with the user and have them change it "
                   "(noo security user set-password).")


# ---------------------------------------------------------------------------
# noo security pki init/issue/issue-gateway/status/rotate
# ---------------------------------------------------------------------------

# trust-ca / untrust-ca are NATIVE ONLY (noo-cli security_local.rs) — the
# Python versions and their shared impl (onboard/ca_trust.py) were removed
# on 2026-08-06 after the trust-store flip (history in git log before that)
# (Linux store always; Windows store is legacy cleanup). Keeping a second,
# unreachable implementation here is how divergence ships.


@pki_app.command("init")
def pki_init() -> None:
    """Generate a cluster CA certificate."""
    try:
        from .pki.ca import ClusterCA
    except ImportError:
        print_error("PKI module not available (cryptography package required)")
        raise typer.Exit(1)

    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    ca = ClusterCA(pki_dir)
    if (pki_dir / "ca.crt").exists():
        console.print("[yellow]CA already exists. Use --force to regenerate (not implemented).[/]")
        return
    ca.generate_ca()
    console.print(f"[green]Cluster CA created at {pki_dir}/ca.crt[/]")


@pki_app.command("issue")
def pki_issue(
    node_id: str = typer.Argument(..., help="Node identifier"),
    ip: str = typer.Argument(..., help="Node IP address"),
    days: int = typer.Option(90, help="Certificate validity in days"),
    extra_san: list[str] = typer.Option([], "--san", help="Extra DNS SANs (e.g. --san node-agent)"),
) -> None:
    """Issue a TLS certificate for a cluster node."""
    try:
        from .pki.ca import ClusterCA
    except ImportError:
        print_error("PKI module not available")
        raise typer.Exit(1)

    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    ca = ClusterCA(pki_dir)
    cert_path, key_path = ca.issue_node_cert(node_id, ip, days=days, extra_sans=extra_san or None)
    console.print(f"[green]Node cert: {cert_path}[/]")
    console.print(f"[green]Node key:  {key_path}[/]")


@pki_app.command("issue-service")
def pki_issue_service(
    service: str = typer.Argument(..., help="Service name, e.g. reranker"),
    san: list[str] = typer.Option(
        [], "--san", help="Extra DNS SANs (e.g. --san stunnel-reranker --san noo-reranker)"
    ),
    days: int = typer.Option(90, help="Certificate validity in days"),
) -> None:
    """Issue an mTLS server certificate for an internal service.

    Service certs are normally minted during onboarding; use this to add one
    to a running cluster (e.g. the reranker) without re-onboarding. Writes to
    ``<NOO_PKI_DIR>/services/<service>/service.{crt,key}``.
    """
    try:
        from .pki.ca import ClusterCA
    except ImportError:
        print_error("PKI module not available")
        raise typer.Exit(1)

    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    ca = ClusterCA(pki_dir)
    cert_path, key_path = ca.issue_service_cert(service, hostnames=san or None)
    console.print(f"[green]Service cert: {cert_path}[/]")
    console.print(f"[green]Service key:  {key_path}[/]")


@pki_app.command("issue-gateway")
def pki_issue_gateway(
    hostname: str = typer.Argument("gateway", help="Gateway hostname"),
    ip: str = typer.Argument("127.0.0.1", help="Gateway IP"),
    days: int = typer.Option(90, help="Certificate validity in days"),
    extra_ip: list[str] = typer.Option(
        [], "--extra-ip",
        help="Additional IP SANs (repeatable) — e.g. the tailnet overlay IP "
             "when NOO_GATEWAY_URL points at it."),
    extra_san: list[str] = typer.Option(
        [], "--extra-san",
        help="Additional DNS SANs (repeatable) — e.g. the MagicDNS name."),
) -> None:
    """Issue a TLS certificate for the gateway."""
    try:
        from .pki.ca import ClusterCA
    except ImportError:
        print_error("PKI module not available")
        raise typer.Exit(1)

    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    ca = ClusterCA(pki_dir)
    cert_path, key_path = ca.issue_gateway_cert(
        hostname, ip, days=days,
        extra_sans=list(extra_san) or None,
        extra_ips=list(extra_ip) or None,
    )
    console.print(f"[green]Gateway cert: {cert_path}[/]")
    console.print(f"[green]Gateway key:  {key_path}[/]")


@pki_app.command("status")
def pki_status() -> None:
    """List all certificates and their expiry dates."""
    try:
        from .pki.ca import ClusterCA
    except ImportError:
        print_error("PKI module not available")
        raise typer.Exit(1)

    from rich.table import Table

    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    ca = ClusterCA(pki_dir)
    certs = ca.get_expiring_certs(warn_days=9999)  # list all

    if not certs:
        console.print("[dim]No certificates found. Run 'noo security pki init' first.[/]")
        return

    table = Table(title="Cluster Certificates")
    table.add_column("Name")
    table.add_column("Expires")
    table.add_column("Days Left")
    table.add_column("Status")

    for cert_info in certs:
        days_left = cert_info.get("days_left", 0)
        if days_left < 0:
            status = "[red]EXPIRED[/]"
        elif days_left < 30:
            status = "[yellow]EXPIRING SOON[/]"
        else:
            status = "[green]OK[/]"
        table.add_row(
            cert_info.get("name", ""),
            cert_info.get("expires", ""),
            str(days_left),
            status,
        )
    console.print(table)


@pki_app.command("rotate")
def pki_rotate(
    node_id: str = typer.Argument(..., help="Node ID to rotate cert for"),
    ip: str = typer.Argument(..., help="Node IP address"),
    days: int = typer.Option(90, help="New cert validity"),
) -> None:
    """Re-issue a certificate for a node (rotate)."""
    try:
        from .pki.ca import ClusterCA
    except ImportError:
        print_error("PKI module not available")
        raise typer.Exit(1)

    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    ca = ClusterCA(pki_dir)
    ca.revoke_node_cert(node_id)
    cert_path, key_path = ca.issue_node_cert(node_id, ip, days=days)
    console.print(f"[green]Rotated cert for {node_id}[/]")
    console.print(f"  cert: {cert_path}")
    console.print(f"  key:  {key_path}")


def _cert_consumers(name: str, role: str) -> list[str]:
    """Container names that must reload when this cert rotates."""
    import platform
    from .pki.consumers import cert_consumers
    return cert_consumers(name, role, local_hostname=platform.node())


def _running_containers() -> set[str]:
    import subprocess as sp
    try:
        out = sp.run(["docker", "ps", "--format", "{{.Names}}"],
                     capture_output=True, text=True, timeout=15)
        return set(out.stdout.split())
    except Exception:
        return set()


def _probe_health(containers: list[str], timeout: int = 150) -> tuple[bool, str]:
    """All restarted containers running; gateway serving /health if present."""
    import subprocess as sp
    import time as _time
    import httpx as _httpx
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        states = {}
        for c in containers:
            r = sp.run(["docker", "inspect", "-f",
                        "{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", c],
                       capture_output=True, text=True)
            states[c] = r.stdout.strip()
        bad = [c for c, s in states.items()
               if not s.startswith("true") or "unhealthy" in s]
        gw_ok = True
        if "noo-gateway" in containers:
            # Verify against the cluster CA: the
            # gateway's leaf names `localhost`. Never verify=False — a probe
            # that accepts any certificate proves nothing about the leaf the
            # rotation just installed. No readable CA: the system store,
            # which carries it after `noo security trust-ca`.
            _ca = os.environ.get("NOO_TLS_CA", "").strip() or str(
                Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki"))) / "ca.crt")
            _verify = _ca if os.path.isfile(_ca) else True
            try:
                gw_ok = _httpx.get("https://localhost:8080/health",
                                   verify=_verify, timeout=4).status_code == 200
            except Exception:
                gw_ok = False
        if not bad and gw_ok:
            return True, "all consumers healthy"
        _time.sleep(5)
    return False, f"unhealthy after {timeout}s: {bad or []}{' gateway /health failing' if not gw_ok else ''}"


@pki_app.command("rotate-all")
def pki_rotate_all(
    warn_days: int = typer.Option(30, help="Rotate certs expiring within this many days"),
    new_days: int = typer.Option(90, help="Validity for newly issued certs"),
    force: bool = typer.Option(False, "--force", help="Skip confirmation"),
    reload: bool = typer.Option(True, "--reload/--no-reload",
                                help="Restart affected containers, health-probe, and auto-revert on failure"),
) -> None:
    """Rotate all leaf certificates expiring soon — and reload their consumers.

    Scans the PKI directory for certificates expiring within --warn-days,
    backs them up, re-issues each one, restarts the running containers that
    serve them (gateway last), health-probes, and REVERTS the rotation +
    restarts again if consumers come up unhealthy. The CA is never rotated.
    """
    try:
        from .pki.ca import ClusterCA
    except ImportError:
        print_error("PKI module not available (cryptography package required)")
        raise typer.Exit(1)

    from rich.table import Table

    pki_dir = Path(os.getenv("NOO_PKI_DIR", os.path.expanduser("~/.config/mesh/pki")))
    ca = ClusterCA(pki_dir)

    expiring = ca.get_expiring_certs(warn_days=warn_days)
    if not expiring:
        console.print(f"[green]No certificates expiring within {warn_days} days.[/]")
        return

    console.print(f"[yellow]{len(expiring)} certificate(s) expiring within {warn_days} days:[/]")
    for c in expiring:
        console.print(f"  - {c['name']}: {c['days_left']} days left")

    if not force:
        from .cli_utils import confirm_destructive
        confirm_destructive("rotate", f"{len(expiring)} expiring certificate(s)")

    # Backup every expiring cert+key so a failed reload can revert
    import shutil as _shutil
    import time as _time
    backup_dir = pki_dir / f".rotate-backup-{int(_time.time())}"
    for c in expiring:
        src_crt = Path(c["path"])
        for src in (src_crt, src_crt.with_suffix(".key")):
            if src.exists():
                dst = backup_dir / src.relative_to(pki_dir)
                dst.parent.mkdir(parents=True, exist_ok=True)
                _shutil.copy2(src, dst)

    results = ca.rotate_all_expiring(warn_days=warn_days, new_days=new_days)

    table = Table(title="Rotation Results")
    table.add_column("Certificate")
    table.add_column("Role")
    table.add_column("Status")
    table.add_column("Detail")

    gateway_rotated = False
    for r in results:
        status_color = {"rotated": "green", "skipped": "yellow", "error": "red"}.get(r["status"], "white")
        table.add_row(
            r["name"],
            r["role"],
            f"[{status_color}]{r['status']}[/]",
            r.get("error", ""),
        )
        if r["role"] == "gateway" and r["status"] == "rotated":
            gateway_rotated = True

    console.print(table)

    rotated = [r for r in results if r["status"] == "rotated"]
    if not rotated:
        return

    if not reload:
        if gateway_rotated:
            console.print(
                "\n[yellow]The gateway certificate was rotated. "
                "Restart the gateway for the new cert to take effect:[/]\n"
                "  noo stack restart"
            )
        console.print(f"[dim]Backup kept at {backup_dir}[/]")
        return

    # ── Reload consumers: services first, gateway last ──
    import subprocess as _sp
    running = _running_containers()
    to_restart: list[str] = []
    for r in rotated:
        for c in _cert_consumers(r["name"], r["role"]):
            if c in running and c not in to_restart:
                to_restart.append(c)
    to_restart.sort(key=lambda c: c == "noo-gateway")  # gateway last

    if not to_restart:
        console.print("[dim]No running consumers to reload.[/]")
        return

    console.print(f"\nReloading consumers: {', '.join(to_restart)}")
    for c in to_restart:
        _sp.run(["docker", "restart", c], capture_output=True, timeout=120)

    ok, detail = _probe_health(to_restart)
    if ok:
        console.print(f"[bold green]✓ Rotation applied — {detail}[/]")
        console.print(f"[dim]Backup kept at {backup_dir} (safe to delete)[/]")
        return

    # ── Revert: restore backed-up certs, restart again ──
    print_error(f"Consumers unhealthy after rotation ({detail}) — REVERTING")
    for src in backup_dir.rglob("*"):
        if src.is_file():
            _shutil.copy2(src, pki_dir / src.relative_to(backup_dir))
    for c in to_restart:
        _sp.run(["docker", "restart", c], capture_output=True, timeout=120)
    ok2, detail2 = _probe_health(to_restart)
    if ok2:
        print_error("Reverted to previous certificates — investigate before retrying "
                    f"(old certs still expire soon; backup at {backup_dir})")
    else:
        print_error(f"REVERT DID NOT RECOVER ({detail2}) — manual intervention needed; "
                    f"original certs are at {backup_dir}")
    raise typer.Exit(1)


# untrust-ca: native only — see the trust-ca note above.


# ---------------------------------------------------------------------------
# noo security service-key  — named keys for external inference consumers
#
# Issuance now lives in the gateway (routes/users.rs, native Rust SQL) —
# same audited path enforcement uses. Stores sha256(key) only; the raw key
# is returned once at issue/rotate. EXTERNAL_INFERENCE_CONTRACT.md
# ---------------------------------------------------------------------------

def _print_issued(data: dict) -> None:
    consumer = data.get("consumer", "")
    scopes = data.get("scopes") or []
    rpm = data.get("rpm_limit")
    console.print(f"[green]Issued service key for consumer '{consumer}'[/]")
    console.print(f"  scopes: [cyan]{', '.join(scopes)}[/]")
    console.print(f"  rpm cap: [cyan]{rpm if rpm is not None else 'uncapped'}[/]")
    console.print("\n[bold yellow]Raw key (shown once — store it now):[/]")
    console.print(f"  {data.get('key', '')}")
    console.print(
        "\n[dim]Client config: base_url=https://<gateway>:8080/api/external, "
        "Authorization: Bearer <key>[/]"
    )


@service_key_app.command("issue")
def service_key_issue(
    consumer: str = typer.Argument(..., help="Consumer name, e.g. noo-trading"),
    scopes: list[str] = typer.Option(
        SERVICE_KEY_SCOPES,
        "--scopes",
        help="Allowed operations (chat, embeddings, rerank, classify, mcp; "
        "mcp:operator opens the operator MCP door and needs an admin --user)",
    ),
    note: Optional[str] = typer.Option(None, "--note", help="Free-form note"),
    rpm: Optional[int] = typer.Option(
        None, "--rpm",
        help="Per-minute request cap for this consumer (omit = uncapped)",
    ),
    user: Optional[str] = typer.Option(
        None, "--user",
        help="Bind the key to a Mesh user — MCP calls then run under that "
             "user's scopes and KB roles instead of the operator's",
    ),
) -> None:
    """Issue a new named service key (prints the raw key once).

    Without ``--user`` the key is a MACHINE credential: MCP tool calls made
    with it dispatch as the operator (cluster-HMAC), unrestricted. With
    ``--user`` the hub mints that user's own JWT per call, so a read-scope
    user gets read-scope behaviour on the MCP door — the same thing they get
    on the dashboard. Use ``--user`` for a person, omit it for an integration.
    """
    from .cli_utils import is_json_output, output_json

    data = _api("POST", "/api/security/service-keys",
                {"consumer": consumer, "scopes": scopes, "note": note,
                 "rpm": rpm, "user_id": user})
    if is_json_output():
        output_json(data)
    else:
        _print_issued(data)


@service_key_app.command("list")
def service_key_list() -> None:
    """List service keys (never shows raw keys)."""
    from .cli_utils import output_result

    data = _api("GET", "/api/security/service-keys")

    def _render(d: dict) -> None:
        from rich.table import Table

        keys = d.get("keys", [])
        if not keys:
            console.print(
                "[dim]No service keys. Issue one with: "
                "noo security service-key issue <consumer>[/]"
            )
            return
        table = Table(title="Service Keys")
        for col in ("Consumer", "User", "Scopes", "Active", "RPM", "Created",
                    "Last Used", "Note"):
            table.add_column(col)
        for k in keys:
            table.add_row(
                str(k.get("consumer", "")),
                # "operator" is the honest label for an unbound key: that is
                # the identity its calls actually carry, not "none".
                str(k.get("user_id") or "[yellow]operator[/]"),
                str(k.get("scopes", "")),
                "[green]yes[/]" if k.get("active") else "[red]no[/]",
                str(k.get("rpm_limit") if k.get("rpm_limit") is not None else "—"),
                str(k.get("created_at") or "")[:19],
                str(k.get("last_used_at") or "never")[:19],
                str(k.get("note") or ""),
            )
        console.print(table)

    output_result(data, render_table=_render)


@service_key_app.command("revoke")
def service_key_revoke(
    consumer: str = typer.Argument(..., help="Consumer name whose keys to revoke"),
) -> None:
    """Revoke (deactivate) all active keys for a consumer."""
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/service-keys/{consumer}/revoke")
    if is_json_output():
        output_json(data)
        return
    n = data.get("revoked", 0)
    if n:
        console.print(
            f"[yellow]Revoked {n} key(s) for '{consumer}'. "
            "The gateway reflects this within ~60s (key cache TTL).[/]"
        )
    else:
        console.print(f"[dim]No active keys found for '{consumer}'.[/]")


@service_key_app.command("rotate")
def service_key_rotate(
    consumer: str = typer.Argument(..., help="Consumer to rotate"),
    scopes: list[str] = typer.Option(
        SERVICE_KEY_SCOPES,
        "--scopes",
        help="Allowed operations for the new key",
    ),
    note: Optional[str] = typer.Option(None, "--note", help="Free-form note"),
) -> None:
    """Issue a fresh key for a consumer and revoke its previous keys.

    The consumer's existing rpm quota is preserved across rotation.
    """
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/service-keys/{consumer}/rotate",
                {"scopes": scopes, "note": note})
    if is_json_output():
        output_json(data)
        return
    _print_issued(data)
    console.print("[yellow]Previous keys for this consumer were revoked.[/]")


@service_key_app.command("set-quota")
def service_key_set_quota(
    consumer: str = typer.Argument(..., help="Consumer whose quota to set"),
    rpm: int = typer.Argument(
        ..., help="Per-minute request cap (0 = uncapped / remove the cap)"
    ),
) -> None:
    """Set the per-minute request cap for a consumer WITHOUT re-issuing keys.

    Updates every active key for the consumer so they stay consistent (the
    quota bucket is per-consumer). Takes effect within ~60s as the gateway's
    and MCP hub's key caches refresh.
    """
    from .cli_utils import is_json_output, output_json

    data = _api("POST", f"/api/security/service-keys/{consumer}/quota", {"rpm": rpm})
    if is_json_output():
        output_json(data)
        return
    val = data.get("rpm_limit")
    shown = val if val is not None else "uncapped"
    console.print(
        f"[green]Set rpm cap for '{consumer}' → {shown} "
        f"({data.get('updated_keys', 0)} active key(s))[/]"
    )
