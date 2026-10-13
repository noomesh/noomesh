# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Sandbox executor — builds the container spec for a sandbox capability.

the design: this module no longer dials a node agent. It used to POST the
spec to ``https://localhost:8081/api/skills/run`` with the static
``NOO_NODE_AGENT_TOKEN``; from the worker container that address is the
worker itself, so no run ever reached an agent. Agents now admit the
controller's certificate, which only the gateway holds, so ``run_container``
refuses with a reason that names the gateway route (``POST
/api/skills/{name}/run``), which builds the same spec and dials the agent
with the controller's leaf.

Historical notes on the old transport follow.

The executor follows the same pattern as ``BackendManager``: it talks to
node-agent HTTP endpoints to start/manage containers, enforcing sandboxing
constraints defined in each capability's manifest. (Historically these were
called "container skills"; on-disk paths and the NATS subject
``worker.tool.skill`` keep the old name for compatibility.)
"""
from __future__ import annotations

from .. import json_fast as json
import base64
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import structlog

from .skill_manifest import SkillManifest

logger = structlog.get_logger()

# Sandbox container name prefix (kept as "noo-skill-" — node-agent labels and
# operator tooling match on it).
CONTAINER_PREFIX = "noo-skill-"


def _translate_skill_dir(skill_dir: str) -> str:
    """Rewrite a container-local capability path onto the host filesystem.

    The gateway container mounts the repo's ``skills/`` tree at
    ``/app/skills``; node-agent bind mounts need the HOST location of the
    same tree, exported by compose as ``NOO_SKILLS_HOST_DIR``. Unset env
    (host-run dev) or non-matching paths pass through unchanged.
    """
    host_root = os.environ.get("NOO_SKILLS_HOST_DIR", "").rstrip("/")
    if not host_root:
        return skill_dir
    resolved = os.path.abspath(skill_dir)
    container_root = "/app/skills"
    if resolved == container_root or resolved.startswith(container_root + "/"):
        return host_root + resolved[len(container_root):]
    return skill_dir

# Inline skill-file caps — must match node-agent MaxSkillFiles /
# MaxSkillFileBytes (node-agent-go/internal/docker/skills.go).
MAX_SKILL_FILES = 64
MAX_SKILL_FILE_BYTES = 5 * 1024 * 1024


def _collect_skill_files(skill_dir: str) -> Optional[Dict[str, str]]:
    """Read a capability directory into an inline-files map.

    Returns ``{relative_path: base64_content}`` for every regular,
    non-hidden file under *skill_dir*, or ``None`` when the directory
    can't be read or yields nothing (callers then rely on the legacy
    volumes bind-mount). Skips hidden entries and files beyond the
    node-agent's decoded-size cap; stops at the file-count cap.
    """
    try:
        root = os.path.abspath(skill_dir)
        if not os.path.isdir(root):
            return None
        files: Dict[str, str] = {}
        total = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fname in sorted(filenames):
                if fname.startswith("."):
                    continue
                path = os.path.join(dirpath, fname)
                if not os.path.isfile(path):
                    continue
                size = os.path.getsize(path)
                if size > MAX_SKILL_FILE_BYTES or total + size > MAX_SKILL_FILE_BYTES:
                    logger.warning("skill_file_too_large_skipped", path=path, size=size)
                    continue
                if len(files) >= MAX_SKILL_FILES:
                    logger.warning("skill_file_count_cap", skill_dir=skill_dir)
                    return files
                with open(path, "rb") as fh:
                    content = fh.read()
                total += len(content)
                rel = os.path.relpath(path, root)
                files[rel] = base64.b64encode(content).decode("ascii")
        return files or None
    except OSError as exc:
        logger.warning("skill_files_collect_failed", skill_dir=skill_dir, error=str(exc))
        return None


# Why a sandbox run from this process is refused. Shown to
# the model as the tool error and to a pipeline as the step failure.
SANDBOX_REFUSAL = (
    "sandbox capability '{name}' was not run: this process cannot start "
    "containers on a node agent. Agents admit only the controller's "
    "certificate, and the static node-agent token this used to send is "
    "being retired. Run it through the gateway "
    "instead: POST /api/skills/{name}/run, or `noo skills run {name} '<json>'`."
)


# Docker network names mapped from permission levels
NETWORK_MAP = {
    "none": "none",
    "restricted": "noo-skill-restricted",
    "full": "bridge",
    "host": "host",
}


@dataclass
class SandboxResult:
    """Result of a sandbox-capability execution."""

    success: bool
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0
    container_id: Optional[str] = None
    node_id: Optional[str] = None

    def to_prompt(self) -> str:
        """Format result for inclusion in an LLM prompt."""
        if self.success:
            text = json.dumps(self.output, indent=2, default=str)
            return f"Skill output:\n```json\n{text}\n```"
        return f"Skill error: {self.error}"


# Backward-compat alias (pre-fold name).
SkillResult = SandboxResult


class SandboxExecutor:
    """Execute sandbox capabilities in Docker containers via node-agent.

    This class provides a clean interface for running arbitrary containers
    with structured JSON input/output. Other components (e.g. browser tool)
    can reuse the ``run_container`` method directly.
    """

    def __init__(self, **_ignored: Any):
        """No node-agent address any more.

        The executor used to take ``get_agent_url`` / ``default_agent_url``
        and dial the agent itself. Nothing ever passed either, so every run
        went to ``https://localhost:8081``, which inside the worker container
        is the worker itself. Old keyword arguments are accepted and ignored
        so a stale ``init_sandbox_executor(...)`` call does not crash.
        """

    # ------------------------------------------------------------------
    # Public: run a sandbox capability from its manifest
    # ------------------------------------------------------------------

    async def execute_skill(
        self,
        manifest: SkillManifest,
        inputs: Dict[str, Any],
        node_id: Optional[str] = None,
    ) -> SkillResult:
        """Run a sandbox capability defined by *manifest* with the given *inputs*.

        1. Validate required inputs.
        2. Build Docker container spec from manifest (the capability
           directory is bind-mounted read-only at ``/skill`` so the
           manifest's default ``python /skill/run.py`` command works).
        3. Call ``run_container`` to execute via node-agent.
        4. Parse stdout as JSON output.
        """
        # Validate required inputs
        missing = [p for p in manifest.required_inputs() if p not in inputs]
        if missing:
            return SkillResult(
                success=False,
                error=f"Missing required inputs: {', '.join(missing)}",
            )

        container_name = f"{CONTAINER_PREFIX}{manifest.name}-{uuid.uuid4().hex[:8]}"

        # Build environment from inputs (serialised as JSON)
        env = {"SKILL_INPUT": json.dumps(inputs, default=str)}

        # Determine network mode
        net_mode = NETWORK_MAP.get(manifest.container.network, "none")

        # GPU reservation
        gpu_request = manifest.container.gpu

        # Mount the capability directory (manifest.yml + run.py) at /skill so
        # the container command can execute it. Node-agent bind-mounts
        # host_path -> container_path, so the source must be a HOST path —
        # inside the gateway container the tree lives at /app/skills and
        # NOO_SKILLS_HOST_DIR (set by compose) supplies the host prefix.
        volumes = (
            {_translate_skill_dir(manifest.skill_dir): "/skill"}
            if manifest.skill_dir
            else None
        )

        # Preferred transport: ship the capability files inline. The
        # bind-mount above only resolves on the controller's own host
        # filesystem — remote nodes fail with "bind source path does not
        # exist". New node-agents materialize `files` at /skill and ignore
        # `volumes`; old agents ignore the unknown field (legacy fallback).
        files = _collect_skill_files(manifest.skill_dir) if manifest.skill_dir else None

        return await self.run_container(
            image=manifest.container.image,
            command=list(manifest.container.command),
            container_name=container_name,
            env=env,
            memory_limit=manifest.container.memory_limit,
            network_mode=net_mode,
            gpu=gpu_request,
            timeout=manifest.container.timeout,
            node_id=node_id,
            volumes=volumes,
            files=files,
            skill_name=manifest.name,
        )

    # ------------------------------------------------------------------
    # Public: generic container execution (reusable by browser tool etc.)
    # ------------------------------------------------------------------

    async def run_container(
        self,
        image: str,
        command: list[str],
        *,
        container_name: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        memory_limit: str = "256m",
        network_mode: str = "none",
        gpu: bool = False,
        timeout: int = 60,
        node_id: Optional[str] = None,
        volumes: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, str]] = None,
        skill_name: Optional[str] = None,
    ) -> SkillResult:
        """Refuse: this process has no credential a node agent accepts.

        Kept with its full signature so ``execute_skill`` still validates
        inputs and builds the spec (and tests can stand in for the
        transport). The run itself belongs to the gateway, whose
        ``POST /api/skills/{name}/run`` builds the same spec and sends it to
        the agent's ``POST /api/skills/run`` with the controller's leaf.
        Returns a failed ``SandboxResult`` naming that route, so the tool
        bridge shows the reason to the model and a pipeline step raises it.
        """
        # No node agent is dialled from here. The only
        # credential this process held that an agent accepted was the static
        # NOO_NODE_AGENT_TOKEN, and node agents now admit the CONTROLLER's
        # certificate instead. The worker's own leaf is not the controller's,
        # so there is nothing honest left to present. The old target,
        # https://localhost:8081, was the worker's own container anyway: no
        # run from here ever reached an agent. Refuse, and name the doors
        # that do work.
        container_name = container_name or f"{CONTAINER_PREFIX}{uuid.uuid4().hex[:8]}"
        logger.error(
            "sandbox_node_agent_refused",
            image=image,
            container=container_name,
            node_id=node_id or "local",
            capability=skill_name,
            reason="no controller credential in this process",
        )
        return SkillResult(
            success=False,
            error=SANDBOX_REFUSAL.format(name=skill_name or image),
            duration_ms=0.0,
            container_id=None,
            node_id=node_id,
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_output(stdout: str) -> Dict[str, Any]:
        """Try to parse container stdout as JSON, fall back to raw text."""
        stdout = stdout.strip()
        if not stdout:
            return {}
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                return parsed
            return {"result": parsed}
        except json.JSONDecodeError:
            return {"raw_output": stdout}


# Backward-compat alias (pre-fold name).
SkillExecutor = SandboxExecutor


# ---------------------------------------------------------------------------
# Global instance
# ---------------------------------------------------------------------------
_skill_executor: Optional[SandboxExecutor] = None


def get_skill_executor() -> SandboxExecutor:
    """Get or create the global SandboxExecutor."""
    global _skill_executor
    if _skill_executor is None:
        _skill_executor = SandboxExecutor()
    return _skill_executor


def init_skill_executor(**kwargs) -> SandboxExecutor:
    """Create and store the global SandboxExecutor."""
    global _skill_executor
    _skill_executor = SandboxExecutor(**kwargs)
    return _skill_executor


# Preferred post-fold names.
get_sandbox_executor = get_skill_executor
init_sandbox_executor = init_skill_executor
