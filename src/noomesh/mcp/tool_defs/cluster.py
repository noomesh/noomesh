# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster management tools — node status, model cache, model pull."""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import Field

from ..tool_models import AuthLevel, HttpMethod, RiskLevel, ToolDef, register


@register
class PaiClusterStatus(ToolDef):
    """List all cluster nodes with hostname, IP, tier, GPU, status, and running backends.
    Use this to check which nodes are online and what models are loaded."""

    name: ClassVar[str] = "noo_cluster_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/cluster/nodes"
    tags: ClassVar[List[str]] = ["cluster", "status", "external"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, (dict, list)):
            return str(data)
        nodes = data if isinstance(data, list) else data.get("nodes", [])
        if not nodes:
            return "No nodes registered."
        lines = [f"Cluster: {len(nodes)} node(s)\n"]
        for n in nodes:
            hostname = n.get("hostname", n.get("node_id", "?"))
            ip = n.get("ip", n.get("address", "?"))
            tier = n.get("tier", "?")
            gpu = n.get("gpu_model", n.get("capabilities", {}).get("gpu_model", "none"))
            status = n.get("status", "?")
            backends = n.get("running_backends", {})
            if isinstance(backends, dict):
                backend_str = ", ".join(
                    f"{k}({v})" for k, v in backends.items()
                ) or "none"
            elif isinstance(backends, list):
                backend_str = ", ".join(str(b) for b in backends) or "none"
            else:
                backend_str = str(backends) if backends else "none"
            lines.append(
                f"  {hostname} ({ip}) | tier {tier} | GPU: {gpu} | "
                f"{status} | backends: {backend_str}"
            )
        return "\n".join(lines)


@register
class PaiModelsCached(ToolDef):
    """List models currently cached on cluster nodes (downloaded and ready to load)."""

    name: ClassVar[str] = "noo_models_cached"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/models/cached"
    tags: ClassVar[List[str]] = ["cluster", "models"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, (dict, list)):
            return str(data)
        # Expect { node_id: [model, ...], ... } or a list
        if isinstance(data, list):
            if not data:
                return "No cached models found."
            import json as _json
            return _json.dumps(data, indent=2)
        lines = ["Cached models per node:\n"]
        for node_id, models in data.items():
            if isinstance(models, list):
                model_str = ", ".join(str(m) for m in models) or "none"
            else:
                model_str = str(models)
            lines.append(f"  {node_id}: {model_str}")
        return "\n".join(lines) if len(lines) > 1 else "No cached models found."


@register
class PaiModelsPull(ToolDef):
    """Pull (download) a model to a cluster node so it is cached and ready for inference.
    If node_id is omitted, the scheduler picks the best available node."""

    name: ClassVar[str] = "noo_models_pull"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/models/pull"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    tags: ClassVar[List[str]] = ["cluster", "models"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    parallelizable: ClassVar[bool] = False
    timeout_secs: ClassVar[int] = 300

    model: str = Field(description="Model name or HuggingFace repo to pull")
    backend: Optional[str] = Field(default=None, description="Target backend: vllm, ollama, llamacpp")
    node_id: Optional[str] = Field(default=None, description="Specific node to pull the model to")


@register
class PaiClusterDiscover(ToolDef):
    """Probe SSH reachability of inventory + (optional) ad-hoc subnet, and
    cross-check against the cluster registry. Read-only — no enrollment, no
    state changes. Use BEFORE proposing a node-add to see what's reachable
    and which hosts are already enrolled.

    Returns: trusted_hosts (from the inventory file), discovered_hosts
    (subnet scan that aren't in inventory), and cluster_registered
    (already-enrolled nodes). Discovery is read-only: nothing here enrolls
    anything, and every enrolment needs a person on the target machine."""

    name: ClassVar[str] = "noo_cluster_discover"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/cluster/discover"
    tags: ClassVar[List[str]] = ["cluster", "discovery"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    subnet: Optional[str] = Field(
        default=None,
        description="Optional CIDR (e.g. '192.168.1.0/24') to scan in addition to inventory. "
                    "Capped at /20 (4096 hosts) to keep probes fast.",
    )
    skip_unreachable: bool = Field(
        default=True,
        description="When true (default), omit hosts that don't answer on SSH/22. "
                    "Set false to see the complete list including unreachable hosts.",
    )


@register
class PaiClusterPropose(ToolDef):
    """Propose adding a node to the cluster. Creates a row in the
    proposals queue and notifies the user via dashboard / Google Chat /
    Telegram (depending on what's configured).

    Use this when you've found a host (via noo_cluster_discover, or you've
    been told about one) that's reachable and worth adding. The reason
    field becomes the audit trail — explain WHY ("user has a spare GPU
    on 192.0.2.69 that would help with the inference backlog"). The
    user reviews and approves before anything is handed to them to run.

    Approved proposals resolve to bootstrap-token instructions a human runs
    on the target machine — there is no unattended enrolment path, so a
    proposal is a request for attention, never an action."""

    name: ClassVar[str] = "noo_cluster_propose_node"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/cluster/propose"
    tags: ClassVar[List[str]] = ["cluster", "self-modify"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    host: str = Field(description="IP or hostname to propose for enrollment")
    user: str = Field(description="SSH user on the target (e.g. 'ubuntu', 'noo')")
    reason: str = Field(
        description="Why are you proposing this? Logged for audit + shown to "
                    "the user when they review. Examples: 'discovered idle GPU "
                    "node on subnet', 'user asked about adding their laptop'."
    )
    role: Optional[str] = Field(
        default=None,
        description="Optional role hint for the playbook (gpu_tier1, gpu_tier2, "
                    "edge_tier4). Auto-detected from hardware probe if omitted."
    )


@register
class PaiClusterProposals(ToolDef):
    """List pending node-add proposals (or all proposals when status='all').
    Use to check what you've proposed and whether the user has decided on
    them yet."""

    name: ClassVar[str] = "noo_cluster_proposals"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/cluster/proposals"
    tags: ClassVar[List[str]] = ["cluster"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    status: Optional[str] = Field(
        default="pending",
        description="Filter: 'pending' (default), 'needs_bootstrap' "
                    "(approved; the operator must run the bootstrap one-liner "
                    "ON the node), 'rejected', 'failed', or 'all'."
    )
    limit: int = Field(default=50, ge=1, le=500)


@register
class PaiMintBootstrapToken(ToolDef):
    """Mint a single-use enrollment token for adding a machine to the mesh and
    return the ONE supported paste: step 1 `install_command` (installs the noo
    CLI on the new machine), step 2 `enroll_command` (`noo enroll noo1.<blob>`,
    run on the new machine as its user; the blob carries the controller URL,
    the token, the cluster-CA pin and, with with_tailscale, a pre-authorized
    tag:worker Tailscale key), then step 3 `provision_command`
    (`noo cluster provision <node> --wait`, run on the controller). The token
    is single-use, expires, and is bound to node_name. If the Tailscale key
    cannot be minted the call fails; retry with with_tailscale=false when the
    machine already reaches the controller. Use when someone asks to add a
    machine to the cluster."""

    name: ClassVar[str] = "noo_mint_bootstrap_token"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/security/bootstrap-tokens"
    tags: ClassVar[List[str]] = ["cluster", "mesh", "self-modify"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.HIGH

    node_name: str = Field(description="Name the new machine will enroll as (its hostname); redemption from any other hostname is refused")
    with_tailscale: bool = Field(default=True, description="Put a pre-authorized tag:worker Tailscale auth key in the paste so the machine joins the tailnet first")
    ttl_seconds: Optional[int] = Field(default=None, description="Token lifetime in seconds (default 3600, max 86400)")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict) and data.get("enroll_command"):
            return (f"Bootstrap token minted for {data.get('node_name')} "
                    f"(single-use, expires {data.get('expires_at')}).\n"
                    f"Send these to the machine's owner, to run on that machine as their user:\n\n"
                    f"1. {data.get('install_command', '')}\n"
                    f"2. {data['enroll_command']}\n\n"
                    f"Then on the controller: {data.get('provision_command', '')}")
        return str(data)


@register
class PaiMintJoinKeyAlias(PaiMintBootstrapToken):
    """DEPRECATED alias of noo_mint_bootstrap_token — same tool, old name.
    The join-key lane it was named for is retired; this mints a bootstrap
    token for the pull rail exactly as noo_mint_bootstrap_token does. Kept for
    one release so an external client calling the old name keeps working;
    move to noo_mint_bootstrap_token."""

    name: ClassVar[str] = "noo_mint_join_key"
    description: ClassVar[str] = __doc__



@register
class PaiSuggestPlacement(ToolDef):
    """Advise what inference backend a node's HARDWARE can run — given a
    capability manifest (os, gpu_api, vram_gb, …), returns the recommended
    backend + launch mode + reason, and what is NOT viable (e.g. vLLM needs
    an NVIDIA CUDA GPU; a Mac's Metal GPU can't be used from a container).
    Read-only guidance — use before proposing a model/backend for a node,
    or to answer 'what could this machine run?'. Does not change anything.
    Pass node_id (and optionally with={backend, model, role, env}) to also get
    `fit`: whether that node's placements fit its memory, the same verdict
    `noo cluster fit` prints."""

    name: ClassVar[str] = "noo_suggest_placement"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/cluster/suggest-placement"
    tags: ClassVar[List[str]] = ["cluster", "placement", "advisory"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    os: str = Field(default="linux", description="OS: linux, darwin (macOS), windows")
    arch: str = Field(default="amd64", description="CPU arch: amd64, arm64, arm")
    gpu_api: str = Field(default="none", description="GPU API: cuda, metal, rocm, vulkan, none")
    gpu_model: str = Field(default="", description="GPU model name, if known")
    vram_gb: float = Field(default=0.0, description="GPU VRAM in GB (discrete)")
    unified_memory: bool = Field(default=False, description="Apple Silicon shared CPU/GPU RAM")
    can_gpu_passthrough: bool = Field(default=True, description="False for Docker-for-Mac (Metal blocked)")
    override_backend: Optional[str] = Field(default=None, description="Operator override to evaluate")
    node_id: Optional[str] = Field(default=None, description="Also judge this node's memory fit (its placements plus `with`)")
    with_: Optional[Dict[str, Any]] = Field(
        default=None, alias="with",
        description="A placement to try beside the node's existing ones: {backend, model, role, env}")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict) or "recommended" not in data:
            return str(data)
        rec = data["recommended"]
        lines = [f"Recommended: {rec.get('backend')} ({rec.get('launch_mode')}) — {rec.get('reason')}"]
        for w in rec.get("warnings", []):
            lines.append(f"  ⚠ {w}")
        for nv in data.get("not_viable", []):
            lines.append(f"  ✗ not viable: {nv}")
        fit = data.get("fit")
        if isinstance(fit, dict):
            lines.append(f"Memory fit: {fit.get('verdict')} ({fit.get('total_gb', 0):.1f} GB needed)")
            for w in fit.get("warnings", []):
                lines.append(f"  ⚠ {w}")
        return "\n".join(lines)


@register
class PaiReplicationStatus(ToolDef):
    """Show Postgres replication health: this controller's role
    (primary/standby), connected standbys with replay lag, and replication
    slot WAL retention (a dead standby's slot silently retains WAL — watch
    retained_wal). Use to answer 'is the standby in sync / is failover safe?'"""

    name: ClassVar[str] = "noo_replication_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/cluster/replication-status"
    tags: ClassVar[List[str]] = ["cluster", "database", "status", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW


@register
class PaiMetricsQuery(ToolDef):
    """Run a PromQL query against the cluster's Prometheus — the same data
    Grafana shows. Examples: 'up' (what's scraped), 'node_load1' (load),
    'DCGM_FI_DEV_GPU_TEMP or nvidia_smi_temperature_gpu' (GPU temp),
    'rate(http_requests_total[5m])'. Use for 'why is X slow?' questions
    where instantaneous status isn't enough."""

    name: ClassVar[str] = "noo_metrics_query"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/metrics/query"
    tags: ClassVar[List[str]] = ["observability", "metrics", "status"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    query: str = Field(description="PromQL expression")
    time: Optional[str] = Field(default=None, description="RFC3339 or unix timestamp (default: now)")


# `noo_metrics_query` above and the next three are operator-door only: no
# `external` tag, and the gateway refuses their paths to a User-tier token
# (`auth::METRICS_READ_PATHS`). Pinned by
# tests/test_observability_tools_are_operator_door_only.py and
# gateway-rust `user_door_manifest_tools_are_callable_by_a_user_token`.
@register
class PaiMetricsRange(ToolDef):
    """Run a PromQL range query against the cluster's Prometheus — the
    time series behind a Grafana panel. Give a PromQL `query`, a `start` and
    `end` (RFC3339 or unix seconds) and a `step` (seconds or '30s', '5m').
    Refused above 11000 points per series (widen `step`); at most 100 series
    come back and `truncated` says when more matched. Example: query
    'node_load1', start '2026-01-01T00:00:00Z', end '2026-01-01T06:00:00Z',
    step '5m'. Use for 'what happened over the last hours?' questions."""

    name: ClassVar[str] = "noo_metrics_range"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/metrics/range"
    tags: ClassVar[List[str]] = ["observability", "metrics", "status"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    query: str = Field(description="PromQL expression")
    start: str = Field(description="Window start: RFC3339 or unix seconds")
    end: str = Field(description="Window end: RFC3339 or unix seconds")
    step: str = Field(description="Resolution: seconds (60) or a duration (30s, 5m, 1h)")


@register
class PaiMetricsDiscover(ToolDef):
    """Discover what Prometheus holds, so a query can be written. With no
    `label`, lists metric names; with `label` (for example 'job', 'instance',
    'node_id'), lists that label's values. `selector` narrows the lookup to
    matching series (e.g. '{job="node"}'), `prefix` keeps names starting with
    it (e.g. 'noo_'). Sorted, at most 500 returned; `truncated` says when
    more exist."""

    name: ClassVar[str] = "noo_metrics_discover"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/metrics/discover"
    tags: ClassVar[List[str]] = ["observability", "metrics", "status"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    label: Optional[str] = Field(default=None, description="Label to list values of (default: metric names)")
    selector: Optional[str] = Field(default=None, description="Series selector narrowing the lookup, e.g. '{job=\"node\"}'")
    prefix: Optional[str] = Field(default=None, description="Keep only values starting with this")
    limit: Optional[int] = Field(default=None, ge=1, le=500, description="Maximum values (default and cap 500)")


@register
class PaiAlertsList(ToolDef):
    """List the cluster's alerts: every Prometheus alerting rule with its
    state (firing, pending, inactive), severity, summary, when it became
    active and its `for` duration, firing first, plus Alertmanager's own
    view (active, silenced, inhibited alerts). Read-only; it cannot silence
    or acknowledge anything. If Alertmanager is unreachable the answer still
    carries the Prometheus half and an `alertmanager.error`. Use for 'is
    anything alerting?' and 'what is firing and why?'."""

    name: ClassVar[str] = "noo_alerts_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/alerts/list"
    tags: ClassVar[List[str]] = ["observability", "alerts", "status"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    state: Optional[str] = Field(default=None, description="Only rules in this state: firing, pending or inactive")
    alertmanager: Optional[bool] = Field(default=None, description="Include Alertmanager's view (default true)")
