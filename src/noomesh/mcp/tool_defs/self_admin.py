# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Self-administration tools — read logs and check stack status.

All tools here are **read-only**: `noo_logs_tail`, `noo_logs_errors`,
`noo_logs_search`, `noomesh_status`. The agent uses these to diagnose its
own state without asking the user to copy logs.

The three log tools are the agent's review surface over the fleet's logs
(fleet logging plan, phase 5). They sit on the OPERATOR door only — no
`external` tag, pinned by tests/test_log_tools_are_operator_door_only.py —
because the gateway refuses every `/api/logs/*` route to a User-tier login.
`errors` and `tail` are answered from Loki when it is up and from a
`docker logs` scan through the node-agents when it is not; the answer says
which (`backend`), and the formatter repeats it, so a partial scan is never
read as the fleet view. `search` is Loki-only: the gateway BUILDS the
LogQL from the typed fields, so the model never writes LogQL.

There are deliberately no state-changing tools in this module. The model
must not be able to restart or rebuild its own stack: the gateway keeps
zero Docker access, and the host spool that executes such commands is a
lever reserved for a named human operator (`noo stack restart` /
`noo stack rebuild`) plus the autonomy engine's own healing. The
`/api/mesh/restart` and `/api/mesh/rebuild` HTTP endpoints still exist for
that operator and are gated on the Admin role.
"""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


_SINCE_HELP = (
    "Start of the window: a duration ago ('30m', '2h', '1d') or an RFC 3339 "
    "time ('2026-09-28T14:00:00Z'). At most 7 days before `until`."
)
_NODE_HELP = "Node id as the gateway verified it (e.g. 'host3', 'host8'). Omit for every node."
_NAME_HELP = (
    "Exact `name` label: a container ('noo-worker' as Loki carries it; the bare "
    "'worker' is accepted and matches the same streams) or a host unit "
    "('noo-hostd', 'noo-harness')."
)
_SOURCE_HELP = "Where the line came from: docker | journal | self | file. Omit for all."


def _backend_line(data: Any) -> str:
    """One sentence naming who answered — a scan is not the fleet view."""
    if not isinstance(data, dict):
        return ""
    backend = data.get("backend")
    if backend == "loki":
        return "backend: loki (fleet view)"
    why = data.get("loki_error") or "Loki not reachable"
    return f"backend: agent-scan — PARTIAL VIEW, only containers the node-agents could reach ({why})"


def _short_ts(ts: Any) -> str:
    if not isinstance(ts, str):
        return "?"
    return ts.split(".")[0].rstrip("Z")


# ─────────────────────────────────────────────────────────────────────
# Read-only diagnostic tools
# ─────────────────────────────────────────────────────────────────────

@register
class PaiLogsTail(ToolDef):
    """Tail the last N log lines of one container or host unit, oldest first.
    From Loki when it is up (any node, any retained history) or, when it is
    not, that container's `docker logs` through its node-agent — the answer
    says which. Use to inspect a service's recent activity without asking
    the user to paste logs."""

    name: ClassVar[str] = "noo_logs_tail"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/logs/tail"
    tags: ClassVar[List[str]] = ["logs", "diagnostic"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    container: Optional[str] = Field(
        default=None,
        description="Container name (e.g. 'noo-gateway', 'noo-vllm', 'noo-postgres'); "
                    "substring match. Give this or `name`.",
    )
    # `name` would shadow the ClassVar; the wire key stays `name` (alias).
    name_field: Optional[str] = Field(default=None, alias="name", description=_NAME_HELP)
    lines: int = Field(default=200, ge=1, le=5000, description="Number of lines to tail")
    grep: Optional[str] = Field(
        default=None,
        description="Optional regex to filter lines (case-insensitive). "
                    "Examples: 'error|warn', 'snapshot', 'google_chat'.",
    )
    node: Optional[str] = Field(default=None, description=_NODE_HELP)
    source: Optional[str] = Field(default=None, description=_SOURCE_HELP)
    since: Optional[str] = Field(default=None, description=_SINCE_HELP + " Default 24h.")
    until: Optional[str] = Field(default=None, description="End of the window (same forms). Default now.")

    class Config:
        populate_by_name = True

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        entries = data.get("entries")
        lines = data.get("lines") or []
        out: List[str] = []
        if isinstance(entries, list) and len(entries) == len(lines):
            for e in entries:
                out.append(f"{_short_ts(e.get('ts'))} {e.get('node', '?')} {e.get('name', '?')} "
                           f"{e.get('level', '?')} {e.get('line', '')}")
        else:
            out.extend(str(ln) for ln in lines)
        if not out:
            out.append("no log output")
        out.append(f"{len(lines)} line(s), container={data.get('container', '?')} node={data.get('node') or 'any'}")
        out.append(_backend_line(data))
        return "\n".join(out)


@register
class PaiLogsErrors(ToolDef):
    """Recent warnings + errors across the fleet (or one node / container),
    oldest first. From Loki when it is up (`level` error|warn over every
    shipped stream) or, when it is not, a scan of the PAI containers'
    recent output through the node-agents — the answer says which. Use this
    first when diagnosing 'something just broke'."""

    name: ClassVar[str] = "noo_logs_errors"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/logs/errors"
    tags: ClassVar[List[str]] = ["logs", "diagnostic"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    container: Optional[str] = Field(
        default=None,
        description="Container name (substring). Omit to scan all PAI containers.",
    )
    node: Optional[str] = Field(default=None, description=_NODE_HELP)
    # `name` would shadow the ClassVar; the wire key stays `name` (alias).
    name_field: Optional[str] = Field(default=None, alias="name", description=_NAME_HELP)
    source: Optional[str] = Field(default=None, description=_SOURCE_HELP)
    minutes: int = Field(default=15, ge=1, le=240, description="Look-back window (ignored when `since` is given)")
    since: Optional[str] = Field(default=None, description=_SINCE_HELP)
    until: Optional[str] = Field(default=None, description="End of the window (same forms). Default now.")
    limit: int = Field(default=200, ge=1, le=2000, description="Max matches to return")

    class Config:
        populate_by_name = True

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        matches = data.get("matches") or []
        out: List[str] = []
        for m in matches:
            if "ts" in m:
                out.append(f"{_short_ts(m.get('ts'))} {m.get('node', '?')} {m.get('container', '?')} "
                           f"{m.get('level', '?')} {m.get('line', '')}")
            else:
                out.append(f"{m.get('node', '?')} {m.get('container', '?')} {m.get('line', '')}")
        if not out:
            out.append(f"no errors or warnings in the last {data.get('window_minutes', '?')}m")
        tail = f"{len(matches)} match(es), last {data.get('window_minutes', '?')}m"
        if data.get("scanned") is not None:
            tail += f", {data['scanned']} container(s) scanned"
        if data.get("truncated"):
            tail += " (limit reached; narrow the window or raise limit)"
        out.append(tail)
        out.append(_backend_line(data))
        return "\n".join(out)


@register
class PaiLogsSearch(ToolDef):
    """Search the fleet's logs in Loki by node, name, source, level, time
    window and free text — 'what happened on host3 at 14:02' is
    node='host3', since='2026-09-28T14:00:00Z', until='2026-09-28T14:05:00Z';
    'every error in the last hour' is level='error', since='1h'. The
    gateway builds the LogQL from these fields; `text` is a plain substring
    filter, not a regex and not LogQL. Loki-only: when Loki is down this
    tool fails with the reason rather than answering from a partial scan —
    use noo_logs_errors / noo_logs_tail for that."""

    name: ClassVar[str] = "noo_logs_search"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/logs/search"
    tags: ClassVar[List[str]] = ["logs", "diagnostic"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    text: Optional[str] = Field(
        default=None,
        description="Plain substring every returned line must contain (case-sensitive). Not a regex.",
    )
    node: Optional[str] = Field(default=None, description=_NODE_HELP)
    # `name` would shadow the ClassVar; the wire key stays `name` (alias).
    name_field: Optional[str] = Field(default=None, alias="name", description=_NAME_HELP)
    container: Optional[str] = Field(
        default=None, description="Container name, substring match (e.g. 'noo-vllm'); `name` wins when both are given."
    )
    source: Optional[str] = Field(default=None, description=_SOURCE_HELP)
    level: Optional[str] = Field(
        default=None,
        description="debug | info | warn | error | unknown, or several comma-separated ('error,warn'). Omit for all.",
    )
    since: Optional[str] = Field(default=None, description=_SINCE_HELP + " Default 1h.")
    until: Optional[str] = Field(default=None, description="End of the window (same forms). Default now.")
    limit: int = Field(default=200, ge=1, le=2000, description="Max lines to return (hard cap 2000)")
    direction: str = Field(
        default="forward",
        description="'forward' = oldest first (a narrative); 'backward' = newest first (the latest N).",
    )

    class Config:
        populate_by_name = True

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        lines = data.get("lines") or []
        out: List[str] = []
        for e in lines:
            out.append(f"{_short_ts(e.get('ts'))} {e.get('node', '?')} {e.get('name', '?')} "
                       f"{e.get('level', '?')} {e.get('line', '')}")
        if not out:
            out.append("no matching lines")
        tail = f"{len(lines)} line(s) {data.get('start', '?')} → {data.get('end', '?')}"
        if data.get("truncated"):
            tail += " (limit reached; narrow the window or raise limit)"
        if data.get("range_clamped"):
            tail += "; range clamped to 7 days"
        out.append(tail)
        out.append(f"query: {data.get('query', '?')}")
        out.append(_backend_line(data))
        return "\n".join(out)


@register
class PaiMeshStatus(ToolDef):
    """List Docker container states + healthchecks for the whole noomesh stack.
    Returns container name, status (running/restarting/exited/created),
    health (healthy/unhealthy/starting), and uptime. Use to verify the
    cluster is up before debugging deeper."""

    name: ClassVar[str] = "noomesh_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/mesh/status"
    tags: ClassVar[List[str]] = ["cluster", "diagnostic"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW
