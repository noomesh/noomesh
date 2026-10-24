# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""i10a groundwork: NOO_STATE_ROOT holds the sensitive state set, and changes nothing unset.

i10a will put postgres, redis, nats, prometheus, grafana, loki and the gateway
data volume on an encrypted volume. That needs one variable the state volumes
bind under, separate from NOO_DATA_ROOT (models, hf-cache, ollama and images
stay in the clear). This PR introduces the variable; the volume itself comes
later. So the contract is two-sided:

* NOO_STATE_ROOT UNSET (or empty) -> every volume device is byte-for-byte
  what it was: `<NOO_DATA_ROOT>/<name>`, spelled out below;
* NOO_STATE_ROOT=/s -> exactly the state set moves to /s, nothing else does;
  NOO_PG_DATA still wins for postgres.

`claude-config` and `alertmanager-data` are plain named volumes on / today.
Compose cannot switch a volume's type on an env var and re-pointing the name
would orphan the data on every existing install, so they are deliberately NOT
moved here (the PR-D migrate step owns that): asserted below so a quiet move
cannot slip in.
"""

from __future__ import annotations

import json
import os
import re
import subprocess

from tests._compose_projection import BASE, ROOT, _profiles_in, _require_compose_floor

DATA = "/sentinel-data-root"
STATE = "/sentinel-state-root"
LIB_INSTANCE = ROOT / "scripts" / "lib-instance.sh"
MOD_RS = ROOT / "noo-cli/src/onboard/mod.rs"

# volume name -> subdirectory, the state set (and where it binds today).
STATE_VOLUMES = {
    "noo-data": "noo-data",
    "redis-data": "redis",
    "nats-data": "nats",
    "prometheus-data": "prometheus",
    "grafana-data": "grafana",
    "loki-data": "loki",
    "postgres-data": "postgres",
}
# Volumes outside the state set; compose renders only those a selected service
# uses, so each is checked when present (hf-cache must be).
CLEAR_VOLUMES = {"ollama-data": "ollama", "ollama-embed-data": "ollama", "hf-cache": "hf-cache"}


def _volumes(**extra: str) -> dict:
    _require_compose_floor()
    env = {k: v for k, v in os.environ.items() if k not in {
        "NOO_STATE_ROOT", "NOO_PG_DATA", "HF_CACHE_DIR", "IMAGES_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR",
    }}
    env.update({"NOO_DATA_ROOT": DATA, "NOO_IMAGE_PREFIX": "example.invalid/noo", **extra})
    # Compose drops volumes no selected service uses: select every profile.
    profiles = [a for p in sorted(_profiles_in(BASE)) for a in ("--profile", p)]
    out = subprocess.run(
        ["docker", "compose", "-f", str(BASE), *profiles, "config", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, env=env,
    )
    assert out.returncode == 0, out.stderr
    vols = json.loads(out.stdout)["volumes"]
    assert vols, "no volumes rendered - the assertions would be vacuous"
    return vols


def _device(vols: dict, name: str) -> str | None:
    return ((vols[name] or {}).get("driver_opts") or {}).get("device")


def test_unset_state_root_binds_every_volume_exactly_where_it_always_did():
    vols = _volumes()
    for vol, sub in STATE_VOLUMES.items():
        assert _device(vols, vol) == f"{DATA}/{sub}", (vol, _device(vols, vol))
    assert _device(vols, "hf-cache") == f"{DATA}/hf-cache"
    for vol, sub in CLEAR_VOLUMES.items():
        if vol in vols:
            assert _device(vols, vol) == f"{DATA}/{sub}", (vol, _device(vols, vol))
    # An empty value is "unset" too (compose's :-), as the shell and Rust helpers treat it.
    assert _volumes(NOO_STATE_ROOT="") == vols


def test_state_root_moves_exactly_the_state_set():
    vols = _volumes(NOO_STATE_ROOT=STATE)
    for vol, sub in STATE_VOLUMES.items():
        assert _device(vols, vol) == f"{STATE}/{sub}", (vol, _device(vols, vol))
    assert _device(vols, "hf-cache") == f"{DATA}/hf-cache", "hf-cache must stay in the clear"
    for vol, sub in CLEAR_VOLUMES.items():
        if vol in vols:
            assert _device(vols, vol) == f"{DATA}/{sub}", f"{vol} must stay in the clear"


def test_pg_data_keeps_precedence_over_the_state_root():
    vols = _volumes(NOO_STATE_ROOT=STATE, NOO_PG_DATA="/home/u/noo/postgres")
    assert _device(vols, "postgres-data") == "/home/u/noo/postgres"
    assert _device(vols, "redis-data") == f"{STATE}/redis"


def test_models_images_and_hf_cache_binds_ignore_the_state_root():
    _require_compose_floor()
    env = {**os.environ, "NOO_DATA_ROOT": DATA, "NOO_STATE_ROOT": STATE, "NOO_IMAGE_PREFIX": "example.invalid/noo"}
    for k in ("HF_CACHE_DIR", "IMAGES_DIR", "MODELS_DIR", "OLLAMA_DATA_DIR", "NOO_PG_DATA"):
        env.pop(k, None)
    out = subprocess.run(
        ["docker", "compose", "-f", str(BASE), "--profile", "controller", "config", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, env=env,
    )
    assert out.returncode == 0, out.stderr
    srcs = {
        v["source"] for s in json.loads(out.stdout)["services"].values()
        for v in s.get("volumes") or [] if v.get("type") == "bind"
    }
    assert f"{DATA}/models" in srcs and f"{DATA}/images" in srcs, sorted(srcs)
    assert not any(s.startswith(f"{STATE}/models") or s.startswith(f"{STATE}/images") for s in srcs)


def test_claude_config_and_alertmanager_stay_plain_named_volumes():
    vols = _volumes(NOO_STATE_ROOT=STATE)
    for name in ("claude-config", "alertmanager-data"):
        assert not ((vols[name] or {}).get("driver_opts")), f"{name} was re-pointed; that orphans existing data (PR-D's job)"


def test_the_onboard_state_subdirs_const_is_the_compose_state_set():
    text = MOD_RS.read_text()
    m = re.search(r"STATE_SUBDIRS: &\[&str\] = &\[(.*?)\];", text, re.S)
    assert m, "STATE_SUBDIRS not found in onboard/mod.rs"
    assert set(re.findall(r'"([^"]+)"', m.group(1))) == set(STATE_VOLUMES.values())


# ── shell helper ────────────────────────────────────────────────────────────

def _sh(tmp_path, snippet: str, env: dict[str, str] | None = None, dotenv: str | None = None):
    if dotenv is not None:
        (tmp_path / ".env").write_text(dotenv)
    full = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", **(env or {})}
    return subprocess.run(
        ["bash", "-c", f'source "{LIB_INSTANCE}" && {snippet}'],
        cwd=tmp_path, env=full, capture_output=True, text=True, timeout=15,
    )


def test_shell_state_root_defaults_to_the_data_root(tmp_path):
    r = _sh(tmp_path, "noo_state_root", {"NOO_DATA_ROOT": "/srv/noo"})
    assert (r.returncode, r.stdout) == (0, "/srv/noo"), r.stderr


def test_shell_state_root_env_wins_then_dotenv_then_data_root(tmp_path):
    assert _sh(tmp_path, "noo_state_root", {"NOO_DATA_ROOT": "/srv/noo", "NOO_STATE_ROOT": "/s"}).stdout == "/s"
    dotenv = "NOO_DATA_ROOT=/srv/noo\nNOO_STATE_ROOT=/from/dotenv\n"
    assert _sh(tmp_path, "noo_state_root", dotenv=dotenv).stdout == "/from/dotenv"
    assert _sh(tmp_path, "noo_state_root", {"NOO_STATE_ROOT": "/s"}, dotenv=dotenv).stdout == "/s", "env beats .env"
    assert _sh(tmp_path, "noo_state_root", dotenv="NOO_DATA_ROOT=/srv/noo\n").stdout == "/srv/noo"
    assert _sh(tmp_path, "noo_state_root", dotenv="NOO_DATA_ROOT=/srv/noo\nNOO_STATE_ROOT=\n").stdout == "/srv/noo"


def test_shell_state_root_prints_nothing_when_neither_is_set(tmp_path):
    r = _sh(tmp_path, "noo_state_root")
    assert (r.returncode, r.stdout) == (0, "")


def test_instance_guard_also_scopes_a_state_root(tmp_path):
    base = {"NOO_INSTANCE": "t1", "NOO_DATA_ROOT": "/mnt/noo/instances/t1"}
    bad = _sh(tmp_path, "echo PASSED", {**base, "NOO_STATE_ROOT": "/mnt/state"})
    assert bad.returncode != 0 and "PASSED" not in bad.stdout
    assert "OPEN ANOTHER INSTALL'S DATABASES" in bad.stderr and "/mnt/state" in bad.stderr
    ok = _sh(tmp_path, "echo PASSED", {**base, "NOO_STATE_ROOT": "/mnt/state/instances/t1"})
    assert ok.returncode == 0 and "PASSED" in ok.stdout, ok.stderr
    unset = _sh(tmp_path, "echo PASSED", base)
    assert unset.returncode == 0 and "PASSED" in unset.stdout, "unset state root: guard behaves as before"


def test_launchers_follow_the_state_root():
    start = (ROOT / "scripts/noomesh-start.sh").read_text()
    assert start.count('reown_nonroot_dirs "${_state_root:-$_data_root}"') == 2, "redis/grafana re-own must follow the state root"
    clean = (ROOT / "scripts/noomesh-clean.sh").read_text()
    for d in ("redis", "nats"):
        assert f'wipe_data_dir "$STATE_ROOT/{d}"' in clean
    assert 'PG_DATA="$STATE_ROOT/postgres"' in clean
