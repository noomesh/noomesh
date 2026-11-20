# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""scripts/test-start-inputs/run.sh, the real-compose proof, run here against a
model of compose so its own logic (snapshots, greps, case order, exit status)
is checked without docker.

The proof itself is the CI job (.github/workflows/start-inputs.yml), which
runs the same script on a real docker compose. This model does what that
proof relies on and nothing more: `config --format json` merges the -f files
(labels merged), resolves bind and secret paths; `up -d` recreates a
service's container when its config hash (labels included) changed or under
--force-recreate, and keeps a dependent's container. With the label taken out
of the launcher's override, case 2 and 3 go red here too.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "scripts" / "test-start-inputs" / "run.sh"
IMAGE = "docker.io/library/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

FAKE_DOCKER = r'''#!/usr/bin/env python3
import hashlib, json, os, re, sys, uuid
import yaml
STATE = os.environ["FAKE_DOCKER_STATE"]
def load():
    return json.load(open(STATE)) if os.path.exists(STATE) else {"containers": {}}
def save(s):
    json.dump(s, open(STATE, "w"))
a = sys.argv[1:]
if a[:1] == ["compose"]:
    a = a[1:]
    files, rest, i = [], [], 0
    while i < len(a):
        if a[i] == "-f":
            files.append(a[i + 1]); i += 2
        elif a[i] == "--profile":
            i += 2
        else:
            rest.append(a[i]); i += 1
    if rest[:1] == ["version"]:
        print("2.99.0" if "--short" in rest else "Docker Compose version v2.99.0"); sys.exit(0)
    proj = os.environ["COMPOSE_PROJECT_NAME"]
    def config():
        merged = {"services": {}, "secrets": {}}
        for f in files:
            d = yaml.safe_load(open(f)) or {}
            for name, svc in (d.get("services") or {}).items():
                cur = merged["services"].setdefault(name, {})
                for k, v in svc.items():
                    if k == "labels":
                        cur.setdefault("labels", {}).update(v)
                    else:
                        cur[k] = v
            merged["secrets"].update(d.get("secrets") or {})
        img = os.environ.get("NOO_TEST_IMAGE") or sys.exit("NOO_TEST_IMAGE unset")
        for svc in merged["services"].values():
            if "image" in svc:
                svc["image"] = img
            vols = []
            for v in svc.get("volumes") or []:
                src, dst, *mode = v.split(":")
                vols.append({"type": "bind", "source": os.path.abspath(src), "target": dst,
                             **({"read_only": True} if mode == ["ro"] else {})})
            if vols:
                svc["volumes"] = vols
            if "secrets" in svc:
                svc["secrets"] = [{"source": s, "target": s} for s in svc["secrets"]]
        for sec in merged["secrets"].values():
            sec["file"] = os.path.abspath(sec["file"])
        return merged
    if rest[:1] == ["config"]:
        c = config()
        print(json.dumps(c) if "--format" in rest else "\n".join(c["services"])); sys.exit(0)
    if rest[:1] == ["up"]:
        c = config(); s = load()
        force = "--force-recreate" in rest
        for name, svc in c["services"].items():
            h = hashlib.sha256(json.dumps(svc, sort_keys=True).encode()).hexdigest()
            cur = s["containers"].get(name)
            if cur is None or force or cur["hash"] != h:
                s["containers"][name] = {"id": uuid.uuid4().hex * 2, "hash": h, "labels": {
                    "com.docker.compose.project": proj, "com.docker.compose.service": name, **svc.get("labels", {})}}
                print(f" Container {proj}-{name}-1  {'Recreated' if cur else 'Created'}")
        save(s); sys.exit(0)
    if rest[:1] in (["down"], ["stop"]):
        save({"containers": {}}); sys.exit(0)
    if rest[:1] == ["ps"]:
        for c in load()["containers"].values(): print(c["id"])
        sys.exit(0)
    sys.exit(f"fake compose: {rest}")
if a[:1] == ["ps"]:
    for c in load()["containers"].values(): print(c["id"])
    sys.exit(0)
if a[:1] == ["inspect"]:
    fmt = a[a.index("-f") + 1]
    by_id = {c["id"]: c for c in load()["containers"].values()}
    for cid in a[a.index("-f") + 2:]:
        c = by_id[cid]
        out = fmt.replace('{{index .Config.Labels "com.docker.compose.service"}}', c["labels"]["com.docker.compose.service"])
        out = out.replace("{{.Id}}", c["id"]).replace("{{.State.Status}}", "running")
        out = out.replace("{{json .Config.Labels}}", json.dumps(c["labels"], separators=(",", ":")))
        print(out)
    sys.exit(0)
sys.exit(f"fake docker: {a}")
'''


def _fake_bin(tmp: Path) -> Path:
    b = tmp / "bin"
    b.mkdir()
    d = b / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    return b


@pytest.mark.skipif(os.getuid() == 0, reason="case 6 needs a non-root user")
def test_every_case_passes_against_the_model(tmp_path: Path) -> None:
    b = _fake_bin(tmp_path)
    env = {"PATH": f"{b}:{os.environ['PATH']}", "HOME": str(tmp_path), "NOO_TEST_IMAGE": IMAGE,
           "FAKE_DOCKER_STATE": str(tmp_path / "docker.json"), "TMPDIR": str(tmp_path)}
    r = subprocess.run(["bash", str(RUN)], env=env, capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    for n in range(1, 8):
        assert f"START-INPUTS {n} PASS" in out, out
    assert "FAIL" not in out, out
    assert "START-INPUTS: all cases PASS" in out


def test_a_missing_label_fails_the_change_cases(tmp_path: Path) -> None:
    """Red-on-revert, here: a launcher whose override carries no label."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for f in (ROOT / "scripts").glob("lib-*.sh"):
        (scripts / f.name).write_text(f.read_text())
    (scripts / "noo-start-inputs.py").write_text((ROOT / "scripts" / "noo-start-inputs.py").read_text().replace(
        'f"      {LABEL}: {json.dumps(new[name][\'label\'])}"', 'f"      noo.other: \\"x\\""'))
    (scripts / "test-start-inputs").mkdir()
    for f in ("run.sh", "compose.yml"):
        (scripts / "test-start-inputs" / f).write_text((ROOT / "scripts" / "test-start-inputs" / f).read_text())
    for f in ("retired-env-keys",):
        if (ROOT / "scripts" / f).exists():
            (scripts / f).write_text((ROOT / "scripts" / f).read_text())
    b = _fake_bin(tmp_path)
    env = {"PATH": f"{b}:{os.environ['PATH']}", "HOME": str(tmp_path), "NOO_TEST_IMAGE": IMAGE,
           "FAKE_DOCKER_STATE": str(tmp_path / "docker.json"), "TMPDIR": str(tmp_path)}
    r = subprocess.run(["bash", str(scripts / "test-start-inputs" / "run.sh")], env=env, capture_output=True,
                       text=True, timeout=300)
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "START-INPUTS 2 FAIL" in out and "START-INPUTS 3 FAIL" in out, out
