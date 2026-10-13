# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Sandbox-capability execution system for Mesh (containerized "skills").

Directories of ``manifest.yml`` + ``run.py`` executed in a Docker sandbox
via the node-agent. Exposed to pipelines as ``@capability`` entries by
:mod:`noomesh.pipeline.sandbox_capabilities`. The old ``Skill*`` names
are kept as aliases; on-disk paths (``skills/builtins``, ``~/.noo/skills``)
are unchanged.
"""
from .skill_manifest import SkillManifest, SkillPermissions, ContainerConfig
from .skill_registry import (
    SandboxCapabilityRegistry,
    SkillRegistry,
    get_sandbox_registry,
    get_skill_registry,
)
from .skill_executor import (
    SandboxExecutor,
    SandboxResult,
    SkillExecutor,
    SkillResult,
    get_sandbox_executor,
    get_skill_executor,
)

__all__ = [
    "SkillManifest",
    "SkillPermissions",
    "ContainerConfig",
    "SandboxCapabilityRegistry",
    "SkillRegistry",
    "get_sandbox_registry",
    "get_skill_registry",
    "SandboxExecutor",
    "SandboxResult",
    "SkillExecutor",
    "SkillResult",
    "get_sandbox_executor",
    "get_skill_executor",
]
