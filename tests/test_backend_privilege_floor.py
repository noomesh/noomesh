# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The compose backends and their doors carry the agent's privilege floor
(i301, noomesh-internal#300).

The node agent has created every backend with no-new-privileges, CapDrop ALL
and only the entrypoint capabilities (CHOWN, DAC_OVERRIDE, FOWNER, SETGID,
SETUID) since its HostConfig floor; the compose services that run the same
images on the controller had none of it. The stunnel doors run non-root with
no capability and a read-only root (their conf goes to a /tmp tmpfs), and
llama-server, whose write set is empty (docker diff), runs read-only too.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVICES = yaml.safe_load((REPO_ROOT / "docker-compose.cluster.yml").read_text())["services"]

BACKENDS = ["vllm", "vllm-secondary", "llamacpp", "airllm", "ollama", "ollama-embed", "ollama-embed-cpu",
            "tei", "tei-gpu", "reranker"]
AGENT_CAPS = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
DOORS = sorted(n for n in SERVICES if n.startswith("stunnel-"))


def _floor(name: str) -> dict:
    return SERVICES[name]


def test_every_backend_has_the_agents_floor():
    bad = []
    for name in BACKENDS:
        s = _floor(name)
        if "no-new-privileges:true" not in (s.get("security_opt") or []):
            bad.append(f"{name}: no no-new-privileges")
        if s.get("cap_drop") != ["ALL"]:
            bad.append(f"{name}: cap_drop {s.get('cap_drop')}")
        if set(s.get("cap_add") or []) - AGENT_CAPS:
            bad.append(f"{name}: cap_add beyond the agent's set: {s.get('cap_add')}")
    assert not bad, bad


def test_the_agent_floor_is_the_same_set():
    src = (REPO_ROOT / "node-agent-go" / "internal" / "docker" / "backends.go").read_text()
    assert 'backendCapsDefault = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}' in src


def test_every_door_is_non_root_capless_and_read_only():
    assert len(DOORS) == 7, DOORS
    bad = []
    for name in DOORS:
        s = _floor(name)
        if s.get("user") in (None, "", "root", "0"):
            bad.append(f"{name}: user {s.get('user')!r}")
        if s.get("cap_drop") != ["ALL"] or s.get("cap_add"):
            bad.append(f"{name}: caps drop={s.get('cap_drop')} add={s.get('cap_add')}")
        if "no-new-privileges:true" not in (s.get("security_opt") or []):
            bad.append(f"{name}: no no-new-privileges")
        if s.get("read_only") is not True or not any(t.startswith("/tmp:") for t in s.get("tmpfs") or []):
            bad.append(f"{name}: read_only {s.get('read_only')} tmpfs {s.get('tmpfs')}")
    assert not bad, bad


def test_llama_server_runs_read_only():
    s = _floor("llamacpp")
    assert s.get("read_only") is True
    assert any(t.startswith("/tmp:") and "noexec" in t for t in s.get("tmpfs") or [])
