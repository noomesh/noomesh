# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Job scheduler tools — submit, track, cancel jobs; control the scheduler."""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional, Union

from pydantic import Field

from ..tool_models import AuthLevel, HttpMethod, RiskLevel, ToolDef, register


# ═══════════════════════════════════════════════════════════════
# Job management
# ═══════════════════════════════════════════════════════════════

@register
class PaiJobSubmit(ToolDef):
    """Submit a job to the distributed scheduler. Returns a job_id to track with
    noo_job_status. Use force_node to pin the job to one specific node; leave it
    unset to let the scheduler place it on the least-loaded eligible node.

    A user-tier account (the user door) may submit type "inference" only, with an
    object payload up to 64 KiB; force_node is refused, priority is capped at 5,
    timeout_sec at 600, and submits are limited to 30 per hour per account."""

    # The type list here is not decoration: `submit_job_to_redis` rejects any
    # type no executor can run, so a caller that believes an invented type
    # ("embedding", "ingest", "custom" — all previously advertised here) gets a
    # refusal, not a job. The authority is `gateway-rust/src/job_types.rs`;
    # keep this string in step with JOB_TYPES.
    name: ClassVar[str] = "noo_job_submit"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/jobs/submit"
    auth: ClassVar[AuthLevel] = AuthLevel.CLUSTER
    # "external": harnesses submit work through this and let mesh place it
    # on the mesh. Scheduler *control* (pause/drain) stays internal.
    tags: ClassVar[List[str]] = ["scheduler", "jobs", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    type: str = Field(
        description=(
            "Job type. Node-executed: inference, tool_exec, model_download, "
            "model_file, fetch_bundle, background_graph, background_cache. "
            "Gateway-executed: test_run. Any other value is rejected."
        )
    )
    payload: Union[Dict[str, Any], str] = Field(
        description=(
            "Job payload (dict or JSON string). For inference: {\"prompt\": ..., \"model\": ...}. "
            "For model_download: {\"model\": ..., \"profile\": \"ollama\"|\"vllm\"|\"llamacpp\"} — "
            "profile is required (it names the runtime the node pulls the model into)."
        )
    )
    priority: Optional[int] = Field(default=None, description="Priority, higher runs sooner (default 5)")
    backend: Optional[str] = Field(default=None, description="Preferred backend: vllm, ollama, llamacpp")
    force_node: Optional[str] = Field(
        default=None,
        description="Pin the job to this node id — the scheduler dispatches to it and no other",
    )
    timeout_sec: Optional[int] = Field(default=None, description="Job timeout in seconds (default 300)")


@register
class PaiJobStatus(ToolDef):
    """Get the status of a specific job by ID."""

    name: ClassVar[str] = "noo_job_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/jobs/{job_id}"
    tags: ClassVar[List[str]] = ["scheduler", "jobs", "external"]

    job_id: str = Field(description="The job ID to look up")


@register
class PaiJobList(ToolDef):
    """List all jobs in the scheduler queue (pending, running, completed)."""

    name: ClassVar[str] = "noo_job_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/jobs"
    tags: ClassVar[List[str]] = ["scheduler", "jobs", "external"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, (dict, list)):
            return str(data)
        jobs = data if isinstance(data, list) else data.get("jobs", [])
        if not jobs:
            return "No jobs in queue."
        lines = [f"Jobs: {len(jobs)}\n"]
        for j in jobs:
            jid = j.get("job_id", j.get("id", "?"))
            jtype = j.get("type", "?")
            status = j.get("status", "?")
            pri = j.get("priority", 0)
            lines.append(f"  [{jid}] {jtype} | {status} | priority={pri}")
        return "\n".join(lines)


@register
class PaiJobCancel(ToolDef):
    """Cancel a pending or running job. A user-tier account can cancel only jobs its own
    account submitted."""

    name: ClassVar[str] = "noo_job_cancel"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.DELETE
    path: ClassVar[str] = "/api/jobs/{job_id}"
    # Owner-scoped: a user-tier account cancels only jobs its own account
    # submitted (any session); unowned (fleet) jobs are operator-only.
    tags: ClassVar[List[str]] = ["scheduler", "jobs", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    job_id: str = Field(description="The job ID to cancel")


@register
class PaiJobHistory(ToolDef):
    """Retrieve completed job history (most recent first)."""

    name: ClassVar[str] = "noo_job_history"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/jobs/history"
    tags: ClassVar[List[str]] = ["scheduler", "jobs"]

    limit: Optional[int] = Field(default=None, description="Max number of entries to return")


@register
class PaiJobReprioritize(ToolDef):
    """Change the priority of a pending job."""

    name: ClassVar[str] = "noo_job_reprioritize"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/jobs/{job_id}/reprioritize"
    tags: ClassVar[List[str]] = ["scheduler", "jobs"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    job_id: str = Field(description="The job ID to reprioritize")
    priority: int = Field(description="New priority value (higher = sooner)")


# ═══════════════════════════════════════════════════════════════
# Scheduler control
# ═══════════════════════════════════════════════════════════════

@register
class PaiSchedulerStatus(ToolDef):
    """Get scheduler status: running/paused state, queue depth, active jobs."""

    name: ClassVar[str] = "noo_scheduler_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/scheduler/status"
    # Read-only visibility so a harness can make its own submit-vs-local
    # balancing decisions without being able to pause/drain the mesh.
    tags: ClassVar[List[str]] = ["scheduler", "status", "external"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        running = data.get("running", False)
        paused = data.get("paused", False)
        state = "paused" if paused else ("running" if running else "stopped")
        depth = data.get("queue_depth", "?")
        active = data.get("active_jobs", "?")
        return f"Scheduler: {state} | queue: {depth} | active: {active}"


@register
class PaiSchedulerPause(ToolDef):
    """Pause the scheduler — no new jobs will be dispatched until resumed."""

    name: ClassVar[str] = "noo_scheduler_pause"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/scheduler/pause"
    tags: ClassVar[List[str]] = ["scheduler"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM


@register
class PaiSchedulerResume(ToolDef):
    """Resume a paused scheduler — job dispatching will restart."""

    name: ClassVar[str] = "noo_scheduler_resume"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/scheduler/resume"
    tags: ClassVar[List[str]] = ["scheduler"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM


@register
class PaiSchedulerDrain(ToolDef):
    """Drain a node — finish running jobs but accept no new ones.
    Use before maintenance or decommissioning a node."""

    name: ClassVar[str] = "noo_scheduler_drain"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/scheduler/drain/{node_id}"
    tags: ClassVar[List[str]] = ["scheduler", "cluster"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    node_id: str = Field(description="Node ID to drain")


@register
class PaiSchedulerUndrain(ToolDef):
    """Undrain a node — allow the scheduler to dispatch jobs to it again."""

    name: ClassVar[str] = "noo_scheduler_undrain"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/scheduler/undrain/{node_id}"
    tags: ClassVar[List[str]] = ["scheduler", "cluster"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    node_id: str = Field(description="Node ID to undrain")
