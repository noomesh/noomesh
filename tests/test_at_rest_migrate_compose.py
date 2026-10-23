# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""i10a PR-D: the compose side of `noo security at-rest migrate`.

claude-config and alertmanager-data are plain named volumes. A compose volume
cannot change type on an env var, and re-pointing the name would orphan every
existing install's data, so migrate switches the SERVICES to a second pair of
bind volumes under the state root (claude-config-state, alertmanager-data-state)
through NOO_CLAUDE_CONFIG_VOLUME / NOO_ALERTMANAGER_VOLUME, and rollback is
just restoring .env. Unset, nothing changes.
"""

from __future__ import annotations

import json
import os
import subprocess

from tests._compose_projection import BASE, ROOT, _profiles_in, _require_compose_floor

DATA = "/sentinel-data-root"
STATE = "/sentinel-state-root"


def _config(**extra: str) -> dict:
    _require_compose_floor()
    env = {k: v for k, v in os.environ.items() if k not in {
        "NOO_STATE_ROOT", "NOO_PG_DATA", "HF_CACHE_DIR", "IMAGES_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR",
        "NOO_CLAUDE_CONFIG_VOLUME", "NOO_ALERTMANAGER_VOLUME",
    }}
    env.update({"NOO_DATA_ROOT": DATA, "NOO_IMAGE_PREFIX": "example.invalid/noo", **extra})
    profiles = [a for p in sorted(_profiles_in(BASE)) for a in ("--profile", p)]
    out = subprocess.run(
        ["docker", "compose", "-f", str(BASE), *profiles, "config", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, env=env,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _sources(cfg: dict, target: str) -> set[str]:
    """The volume names mounted at `target` by any service."""
    return {
        v["source"]
        for s in cfg["services"].values()
        for v in s.get("volumes") or []
        if v.get("target") == target and v.get("type") == "volume"
    }


def test_unset_the_services_mount_the_plain_named_volumes():
    cfg = _config(NOO_STATE_ROOT=STATE)
    assert _sources(cfg, "/root/.claude") == {"claude-config"}
    assert _sources(cfg, "/alertmanager") == {"alertmanager-data"}
    for name in ("claude-config", "alertmanager-data"):
        assert not (cfg["volumes"][name] or {}).get("driver_opts")
    # Unused, so compose drops them: a non-migrated install never sees them.
    assert "claude-config-state" not in cfg["volumes"]
    assert "alertmanager-data-state" not in cfg["volumes"]


def test_the_migrate_switch_points_both_services_at_binds_under_the_state_root():
    cfg = _config(
        NOO_STATE_ROOT=STATE,
        NOO_CLAUDE_CONFIG_VOLUME="claude-config-state",
        NOO_ALERTMANAGER_VOLUME="alertmanager-data-state",
    )
    assert _sources(cfg, "/root/.claude") == {"claude-config-state"}
    assert _sources(cfg, "/alertmanager") == {"alertmanager-data-state"}
    dev = lambda n: (cfg["volumes"][n].get("driver_opts") or {}).get("device")
    assert dev("claude-config-state") == f"{STATE}/claude-config"
    assert dev("alertmanager-data-state") == f"{STATE}/alertmanager-data"
    assert cfg["volumes"]["claude-config-state"]["driver_opts"]["o"] == "bind"
    # The old named volumes are left alone, so rollback is only an .env edit.
    assert "claude-config" not in cfg["volumes"] or not cfg["volumes"]["claude-config"].get("driver_opts")


def test_the_bind_directories_match_what_the_hostd_copy_verb_accepts():
    # hostd `at-rest copy --name` must accept exactly the directory names the
    # compose binds read (Go: MigrateStateNames; Rust: STATE_COPIES).
    go = (ROOT / "node-agent-go/internal/hostd/atrest_migrate_linux.go").read_text()
    for name in ("claude-config", "alertmanager-data", "pki", "postgres"):
        assert f'"{name}"' in go, name
