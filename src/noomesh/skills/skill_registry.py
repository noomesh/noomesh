# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Sandbox-capability registry — scans manifest directories and maintains the catalogue.

A *sandbox capability* (historically called a "container skill") is a
directory holding a ``manifest.yml`` (I/O params, container config,
permissions) plus its implementation (usually ``run.py``), executed in a
Docker sandbox via the node-agent. Manifests are the declarative contract;
the pipeline capability framework (:mod:`noomesh.pipeline`) exposes each
one as a composable ``@capability`` — see
:mod:`noomesh.pipeline.sandbox_capabilities`.

NOTE on paths: the on-disk directory names are user/deploy-facing and stay
as-is — ``skills/builtins/`` (also scanned by gateway-rust and noo-cli) and
``~/.noo/skills`` / ``$NOO_SKILLS_DIR`` (user data). Only Python identifiers
were renamed.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

import structlog

from .skill_manifest import SkillManifest

logger = structlog.get_logger()

# Default builtin manifests directory (repo-relative; name kept for
# gateway-rust / noo-cli compatibility).
_DEFAULT_BUILTIN_DIR = Path(__file__).resolve().parent.parent.parent.parent / "skills" / "builtins"


class SandboxCapabilityRegistry:
    """Maintains a registry of available sandbox capabilities from local directories."""

    def __init__(
        self,
        builtin_dir: Optional[Path] = None,
        user_dir: Optional[Path] = None,
    ):
        self.builtin_dir = builtin_dir or _DEFAULT_BUILTIN_DIR
        self.user_dir = user_dir or Path(
            os.getenv("NOO_SKILLS_DIR", str(Path.home() / ".noo" / "skills"))
        )
        self._skills: Dict[str, SkillManifest] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def scan(self) -> int:
        """Scan builtin and user directories for capability manifests.

        Returns the total number of manifests loaded.
        """
        self._skills.clear()
        loaded = 0

        for search_dir in (self.builtin_dir, self.user_dir):
            if not search_dir or not search_dir.exists():
                continue
            for manifest_path in search_dir.glob("*/manifest.yml"):
                try:
                    manifest = SkillManifest.from_yaml(manifest_path)
                    self._skills[manifest.name] = manifest
                    loaded += 1
                    logger.info(
                        "sandbox_capability_loaded",
                        name=manifest.name,
                        version=manifest.version,
                        dir=str(manifest_path.parent),
                    )
                except Exception as exc:
                    logger.warning(
                        "sandbox_capability_load_failed",
                        path=str(manifest_path),
                        error=str(exc),
                    )

        logger.info("sandbox_capability_scan_complete", total=loaded)
        return loaded

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[SkillManifest]:
        """Get a capability manifest by name."""
        return self._skills.get(name)

    def list_skills(self) -> List[SkillManifest]:
        """Return all registered capability manifests."""
        return list(self._skills.values())

    def names(self) -> List[str]:
        """Return all registered capability names."""
        return list(self._skills.keys())

    def get_tool_definitions(self) -> List[dict]:
        """Return tool definitions for all capabilities (for agent prompt)."""
        return [s.to_tool_definition() for s in self._skills.values()]


# Backward-compat alias (pre-fold name).
SkillRegistry = SandboxCapabilityRegistry


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------
_skill_registry: Optional[SandboxCapabilityRegistry] = None


def get_skill_registry() -> SandboxCapabilityRegistry:
    """Get or create the global sandbox-capability registry."""
    global _skill_registry
    if _skill_registry is None:
        _skill_registry = SandboxCapabilityRegistry()
        _skill_registry.scan()
    return _skill_registry


# Preferred post-fold name.
get_sandbox_registry = get_skill_registry
