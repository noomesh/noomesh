# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Skill manifest definition — parsed from YAML, validated, immutable."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass(frozen=True)
class SkillParam:
    """A single input or output parameter."""

    name: str
    type: str  # string, number, boolean, array, object
    required: bool = True
    description: str = ""
    default: Any = None


@dataclass(frozen=True)
class SkillPermissions:
    """Sandboxing permissions for a skill container."""

    filesystem: str = "none"   # none | readonly | readwrite
    network: str = "restricted"  # none | restricted | full
    shell: bool = False


@dataclass(frozen=True)
class ContainerConfig:
    """Docker container settings for a skill."""

    image: str = "noo-sandbox-base:latest"
    command: tuple[str, ...] = ("python", "/skill/run.py")
    timeout: int = 60
    memory_limit: str = "256m"
    network: str = "restricted"  # none | restricted | host
    gpu: bool = False


@dataclass(frozen=True)
class SkillManifest:
    """Immutable skill definition parsed from a YAML manifest.

    Each skill lives in its own directory with a ``manifest.yml`` that
    defines metadata, I/O schema, container config and permissions.
    """

    name: str
    version: str
    description: str
    author: str = "noo-builtin"
    inputs: tuple[SkillParam, ...] = ()
    outputs: tuple[SkillParam, ...] = ()
    container: ContainerConfig = ContainerConfig()
    permissions: SkillPermissions = SkillPermissions()
    skill_dir: Optional[str] = None  # abs path to the skill directory

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: Path) -> "SkillManifest":
        """Parse a manifest.yml file into a SkillManifest."""
        with open(path, "r", encoding="utf-8") as fh:
            raw: dict = yaml.safe_load(fh)

        if not isinstance(raw, dict):
            raise ValueError(f"Invalid manifest: {path}")

        name = raw.get("name") or path.parent.name
        version = raw.get("version", "0.0.1")
        description = raw.get("description", "")
        author = raw.get("author", "noo-builtin")

        # Inputs
        inputs_raw: dict = raw.get("inputs", {})
        inputs = tuple(
            SkillParam(
                name=k,
                type=v.get("type", "string") if isinstance(v, dict) else "string",
                required=v.get("required", True) if isinstance(v, dict) else True,
                description=v.get("description", "") if isinstance(v, dict) else "",
                default=v.get("default") if isinstance(v, dict) else None,
            )
            for k, v in inputs_raw.items()
        )

        # Outputs
        outputs_raw: dict = raw.get("outputs", {})
        outputs = tuple(
            SkillParam(
                name=k,
                type=v.get("type", "string") if isinstance(v, dict) else "string",
                required=False,
                description=v.get("description", "") if isinstance(v, dict) else "",
            )
            for k, v in outputs_raw.items()
        )

        # Container config
        c_raw: dict = raw.get("container", {})
        cmd = c_raw.get("command", ["python", "/skill/run.py"])
        image = c_raw.get("image", "noo-sandbox-base:latest")
        # Migration shim: base image renamed noo-skill-base -> noo-sandbox-base
        # (2026-07). Stale user manifests in ~/.noo/skills may still carry the
        # old tag, which no longer exists on any node -- map it to the new name.
        if image == "noo-skill-base:latest":
            image = "noo-sandbox-base:latest"
        container = ContainerConfig(
            image=image,
            command=tuple(cmd) if isinstance(cmd, list) else (cmd,),
            timeout=int(c_raw.get("timeout", 60)),
            memory_limit=str(c_raw.get("memory_limit", "256m")),
            network=c_raw.get("network", "restricted"),
            gpu=bool(c_raw.get("gpu", False)),
        )

        # Permissions
        p_raw: dict = raw.get("permissions", {})
        permissions = SkillPermissions(
            filesystem=p_raw.get("filesystem", "none"),
            network=p_raw.get("network", "restricted"),
            shell=bool(p_raw.get("shell", False)),
        )

        return cls(
            name=name,
            version=version,
            description=description,
            author=author,
            inputs=inputs,
            outputs=outputs,
            container=container,
            permissions=permissions,
            skill_dir=str(path.parent),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def required_inputs(self) -> list[str]:
        """Return names of required input parameters."""
        return [p.name for p in self.inputs if p.required]

    def input_schema(self) -> dict:
        """Return a JSON-schema-style dict describing inputs."""
        return {
            p.name: {
                "type": p.type,
                "required": p.required,
                "description": p.description,
            }
            for p in self.inputs
        }

    def to_tool_definition(self) -> dict:
        """Return a tool definition dict suitable for the agent prompt."""
        return {
            "name": f"skill_{self.name}",
            "description": self.description,
            "parameters": {
                p.name: f"{p.description or p.type} ({'required' if p.required else 'optional'})"
                for p in self.inputs
            },
        }
