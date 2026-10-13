# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Heartbeat scheduler tools — tasks, actions, history, artifacts."""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


@register
class PaiHeartbeatListActions(ToolDef):
    """List available heartbeat actions (daily_briefing, cluster_health, etc.)."""

    name: ClassVar[str] = "noo_heartbeat_list_actions"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/heartbeat/actions"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]


@register
class PaiHeartbeatListTasks(ToolDef):
    """List all scheduled heartbeat tasks with their schedules and enabled state."""

    name: ClassVar[str] = "noo_heartbeat_list_tasks"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/heartbeat/tasks"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]


@register
class PaiScheduleTask(ToolDef):
    """CREATE a recurring scheduled task — does NOT run it immediately.

    Use for "set up a recurring X" / "every day do Y" / "schedule Z weekly".
    The task is registered in the scheduler and fires at the cron time.
    To ALSO run it once right now, pass run_immediately=true. To run an
    EXISTING task immediately, use noo_heartbeat_run_task instead.

    Takes plain English: human-readable `name`, what the task should
    `do`, and `when` to run it. Translates schedule phrases to cron and
    classifies the action automatically. VERIFIES the row landed in the
    DB before returning success — refuses if the slugified id collides
    with an existing task of a different name.

    Examples:
        name="AI Agent Research", do="deep research report on AI agents", when="daily 8am"
        name="Weekly Cluster Check", do="cluster health report", when="every Monday 9am"
        name="Cost Watch", do="cost report", when="every 6 hours", run_immediately=true

    Schedule phrases understood:
      "daily", "daily 8am", "weekly", "every Monday 9am",
      "hourly", "every 6 hours", "every 15 minutes",
      or a 5-field cron expression like "0 8 * * *".

    A task that DELETES data (e.g. "memory cleanup") is not created: it
    becomes a PROPOSAL for the operator to approve, and the answer says so
    (`proposal: true, task_created: false`). Research, reports and checks
    are created directly."""

    name: ClassVar[str] = "noo_schedule_task"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/heartbeat/schedule"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    name_field: str = Field(alias="name", description="Human-readable task name (slugified to id automatically)")
    do_field: str = Field(
        alias="do",
        description="What the task should do, in plain English (e.g. 'deep research report on AI agents')",
    )
    when_field: str = Field(
        alias="when",
        description="When it should run: 'daily 8am', 'every Monday 9am', 'every 6 hours', or a 5-field cron",
    )
    depth: Optional[str] = Field(
        default=None,
        description="For research tasks: 'brief' | 'standard' | 'deep' | 'exhaustive' (default: standard)",
    )
    channel: Optional[str] = Field(default=None, description="Channel to deliver results to (auto-injected from chat context)")
    run_immediately: Optional[bool] = Field(
        default=False,
        description=(
            "If true, ALSO launch the task once right now in addition to "
            "scheduling future runs. Use when the user says 'set this up "
            "AND give me one now'. Default false — pure create, runs at "
            "next cron tick only."
        ),
    )

    class Config:
        populate_by_name = True


@register
class PaiHeartbeatCreateTask(ToolDef):
    """Lower-level: create a heartbeat task with explicit action enum, cron, and config.

    Prefer `noo_schedule_task` for natural-language requests — it does the
    translation work and verifies the row landed. Use this only when you
    need full control (custom action, hand-tuned cron, custom config block).

    A task that DELETES data (a retention or cleanup job, `memory_cleanup`,
    `graph_prune` or `entity_cleanup` with `apply`, ...) is not created or
    changed by this call: it becomes a PROPOSAL for the operator, and a
    person approves it (`noo heartbeat approve <proposal-id>`). The answer
    says `proposal: true, task_created: false`. Enabling such a task is a
    proposal too; disabling or deleting one is allowed. Research, reports,
    digests, previews and dry runs are created directly."""

    name: ClassVar[str] = "noo_heartbeat_create_task"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/heartbeat/tasks"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    id: Optional[str] = Field(default=None, description="Optional task ID (auto-generated if omitted)")
    name_field: str = Field(alias="name", description="Human-readable task name")
    action: str = Field(description="Action to run: daily_briefing, cluster_health, rag_reindex, etc.")
    schedule: str = Field(description="Cron expression (e.g. '0 8 * * *' for 8 AM daily)")
    config: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Action-specific configuration. Common keys: topic/depth/"
            "instructions (research actions), max_iterations, model "
            "(per-task model override, e.g. a cloud model), pipeline "
            "('single' opts a research task out of the phased "
            "gather/write/assemble pipeline)"
        ),
    )
    # POST /api/heartbeat/tasks has always read `channels` and `recipients`
    # (routes/intelligence.rs), but this tool never offered them — so every
    # task created through an MCP door was born with no destination. It ran on
    # schedule, produced its report, and delivered to nobody. `noo heartbeat
    # add --channel/--recipient` could express this; the door could not.
    #
    # Positional: channels[i] is delivered to recipients[i].
    channels: Optional[List[str]] = Field(
        default=None,
        description=(
            "Channels to deliver the result to, e.g. ['google_chat'] or "
            "['telegram']. Positional with `recipients`. Omit for a "
            "maintenance task whose result nobody needs to read."
        ),
    )
    recipients: Optional[List[str]] = Field(
        default=None,
        description=(
            "Address per channel, positional with `channels`. For "
            "google_chat this is a space resource name ('spaces/<id>'); for "
            "telegram, a chat id. A channel with no matching recipient "
            "cannot deliver."
        ),
    )
    enabled: bool = Field(default=True, description="Whether the task starts enabled")
    created_by: str = Field(default="agent", description="Creator identifier")

    class Config:
        populate_by_name = True


@register
class PaiHeartbeatDeleteTask(ToolDef):
    """Delete a scheduled heartbeat task."""

    name: ClassVar[str] = "noo_heartbeat_delete_task"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.DELETE
    path: ClassVar[str] = "/api/heartbeat/tasks/{task_id}"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    task_id: str = Field(description="ID of the task to delete")


@register
class PaiHeartbeatRunTask(ToolDef):
    """Manually trigger a heartbeat task to run immediately."""

    name: ClassVar[str] = "noo_heartbeat_run_task"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/heartbeat/tasks/{task_id}/run"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    task_id: str = Field(description="ID of the task to run")


@register
class PaiHeartbeatTaskHistory(ToolDef):
    """View execution history for heartbeat tasks."""

    name: ClassVar[str] = "noo_heartbeat_task_history"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/heartbeat/history"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]

    task_id: Optional[str] = Field(default=None, description="Filter history by task ID")
    limit: Optional[int] = Field(default=None, description="Maximum number of history entries")


@register
class PaiHeartbeatStatus(ToolDef):
    """Get heartbeat scheduler status: running state, task count, next run times."""

    name: ClassVar[str] = "noo_heartbeat_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/heartbeat/status"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler", "status"]


@register
class PaiHeartbeatToggleTask(ToolDef):
    """Enable or disable a scheduled heartbeat task."""

    name: ClassVar[str] = "noo_heartbeat_toggle_task"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.PUT
    path: ClassVar[str] = "/api/heartbeat/tasks/{task_id}/toggle"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    task_id: str = Field(description="ID of the task to toggle")
    enabled: bool = Field(description="Whether to enable (true) or disable (false) the task")


@register
class PaiHeartbeatGetArtifacts(ToolDef):
    """Retrieve heartbeat task artifacts (generated reports, logs) by path."""

    name: ClassVar[str] = "noo_heartbeat_get_artifacts"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/heartbeat/artifacts"
    tags: ClassVar[List[str]] = ["heartbeat", "scheduler"]

    path_param: str = Field(alias="path", description="Artifact path to retrieve")

    class Config:
        populate_by_name = True
