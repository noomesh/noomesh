# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The install-matrix harness (2026-11-12): what it keeps out of PUBLIC logs,
how it times and records a step, and the release size math."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CELL = ROOT / "scripts" / "install-cell" / "cell.py"
LIB = ROOT / "scripts" / "install-cell" / "lib.sh"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = _load("install_cell", CELL)
SIZE = _load("release_size", ROOT / "scripts" / "release-size-report.py")

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MX0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"
SECRET_LINES = [
    "  join key: noo1.QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo.abc",
    f"Authorization: Bearer {JWT}",
    "admin password: Tr0ub4dor&3-horse",
    "NOO_CLUSTER_TOKEN=s3cr3t-value-123",
    "export GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpams=",
]


def _redact(text: str) -> str:
    return subprocess.run([sys.executable, str(CELL), "redact"], input=text, capture_output=True,
                          text=True, check=True).stdout


def test_secrets_never_reach_a_public_log():
    out = _redact("\n".join(SECRET_LINES) + "\n")
    for leaked in ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo", JWT, "Tr0ub4dor", "s3cr3t-value", "ghp_abcdef",
                   "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"):
        assert leaked not in out, (leaked, out)
    assert out.count("[REDACTED]") >= len(SECRET_LINES)
    assert "join key: " in out and "admin password: " in out, "the label stays, only the value goes"


def test_a_pem_block_is_masked_whole_and_digests_stay_readable():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabc\n-----END PRIVATE KEY-----\nafter\n"
    out = _redact(pem)
    assert "MIIEv" not in out and "abc" not in out and out.endswith("after\n")
    digest = "sha256:" + "ab" * 32
    assert digest in _redact(f"image digest {digest}\n"), "a digest is evidence, not a secret"


def test_the_upload_scan_refuses_anything_secret_shaped(tmp_path):
    (tmp_path / "ok.log").write_text(_redact("\n".join(SECRET_LINES) + "\n"))
    scan = lambda: subprocess.run([sys.executable, str(CELL), "scan", str(tmp_path)],  # noqa: E731
                                  capture_output=True, text=True)
    assert scan().returncode == 0, scan().stderr
    for raw in SECRET_LINES:
        (tmp_path / "leak.log").write_text(raw + "\n")
        r = scan()
        assert r.returncode == 3, (raw, r.stderr)
    (tmp_path / "leak.log").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    assert scan().returncode == 3


def test_a_step_that_hangs_is_killed_with_its_children_at_the_timeout():
    t0 = time.time()
    r = subprocess.run([sys.executable, str(CELL), "run", "2", "--", "sh", "-c", "sleep 60 & sleep 60"],
                       capture_output=True, text=True)
    assert r.returncode == 124 and time.time() - t0 < 30
    assert "TIMEOUT after 2s" in r.stdout


def test_a_record_names_the_first_error_prompts_and_warnings(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("pulling\nPROMPT: Admin email [admin@local]\nContinue? [Y/n]\n"
                   "! verify: tempo not ready\noperator alert: TargetDown loki\n"
                   "Error: compose up failed: port 443 in use\nlater error\n")
    r = C.record("stack-start", 1, 42, str(log))
    assert r["first_error"] == "Error: compose up failed: port 443 in use"
    assert len(r["prompts"]) == 2 and len(r["warnings"]) == 2
    assert C.record("x", 0, 1, str(log))["first_error"] == "", "a passing step has no first error"


def test_lib_step_redacts_records_and_returns_the_exit_code(tmp_path):
    out = tmp_path / "out"
    script = (f'set -uo pipefail; OUT="{out}"; CELL=t; . "{LIB}"; '
              'step leak 30 -- sh -c "echo admin password: hunter2hunter2; echo Error: boom; exit 7"; echo "rc=$?"')
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert "rc=7" in r.stdout and "hunter2" not in r.stdout, r.stdout
    rec = json.loads((out / "steps.jsonl").read_text().splitlines()[0])
    assert rec["step"] == "leak" and rec["rc"] == 7 and rec["first_error"] == "Error: boom"
    assert "hunter2" not in (out / "logs" / "leak.log").read_text()


def test_the_summary_names_the_failed_step_and_ignores_leftover_rcs(tmp_path):
    steps = [{"step": "install", "rc": 0, "seconds": 3, "first_error": "", "prompts": [], "warnings": ["! w"], "tail": []},
             {"step": "leftover-docker", "rc": 1, "seconds": 1, "first_error": "LEFTOVER volume noomesh_pg",
              "prompts": [], "warnings": [], "tail": []}]
    (tmp_path / "steps.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c", "limits": ["no GPU"]}))
    s = C.summarize(tmp_path)
    assert s["result"] == "pass" and s["warning_count"] == 1
    steps[0]["rc"] = 2
    steps[0]["first_error"] = "curl: (22) 404"
    (tmp_path / "steps.jsonl").write_text("\n".join(json.dumps(s) for s in steps) + "\n")
    s = C.summarize(tmp_path)
    assert s["result"] == "fail" and s["failed_step"] == "install" and s["first_error"] == "curl: (22) 404"
    assert "Not covered here:** no GPU" in (tmp_path / "summary.md").read_text()
    # A mode whose hook is not written yet ran only the box step: "not run", never "pass".
    (tmp_path / "steps.jsonl").write_text(json.dumps({**steps[0], "rc": 0}) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c", "not_run": "onboard-interactive.sh not written yet"}))
    assert C.summarize(tmp_path)["result"] == "not run"


# ---- release size math ------------------------------------------------------

def L(d, s):
    return {"digest": d, "size": s}


def test_upgrade_bytes_are_the_layers_the_previous_final_lacks():
    s = SIZE.sizes([L("a", 10), L("b", 20), L("c", 30)], [L("a", 10)], [L("a", 10), L("b", 20)])
    assert s == {"total_bytes": 60, "own_bytes": 50, "upgrade_bytes": 30}
    assert SIZE.sizes([L("a", 10)], None, None) == {"total_bytes": 10, "own_bytes": None, "upgrade_bytes": 10}, \
        "no base: own is unknown (never a guess); no previous final: everything is downloaded"


def test_the_base_is_the_last_from_resolved_to_our_mirrors():
    df = ("ARG DHI_REGISTRY=dhi.io\nFROM --platform=$BUILDPLATFORM ${DHI_REGISTRY}/golang:1.26@sha256:" + "1" * 64
          + " AS b\nFROM ${DHI_REGISTRY}/alpine-base:3.22@sha256:" + "2" * 64 + "\n")
    assert SIZE.resolve_base(SIZE.final_from(df), {}) == "ghcr.io/noomesh/dhi/alpine-base@sha256:" + "2" * 64
    assert SIZE.resolve_base("${HUB_MIRROR}/library/python:3.12-slim@sha256:" + "3" * 64, {}) == \
        "ghcr.io/noomesh/mirror/library/python@sha256:" + "3" * 64
    bases = {"deps-core": "sha256:" + "4" * 64}
    assert SIZE.resolve_base("${DEPS_CORE}", bases) == "ghcr.io/noomesh/dhi/deps-core@sha256:" + "4" * 64
    assert SIZE.resolve_base("${DEPS_BASE}", bases) is None
    assert SIZE.resolve_base("python:3.12", {}) is None, "an unpinned base is not resolved by name"
    assert SIZE.parse_lock("# stack v1\ngateway@sha256:" + "a" * 64 + "\nsource:trellion@abc\n") == \
        {"gateway": "sha256:" + "a" * 64}


def test_the_workflow_is_hosted_only_reports_only_and_reachable_from_any_tree():
    import yaml
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "install-matrix.yml").read_text())
    on = doc[True]
    assert on["push"]["branches"] == ["ci/install-matrix/**"], "must never match the mutant branches"
    assert "schedule" in on and "workflow_dispatch" in on
    assert doc["permissions"] == {"contents": "read"}
    text = (ROOT / ".github" / "workflows" / "install-matrix.yml").read_text()
    assert "secrets." not in text, "a cell runs our released installer: it gets no secret"
    cells = {r["cell"]: r for r in doc["jobs"]["cell"]["strategy"]["matrix"]["include"]}
    assert cells["ubuntu-24.04-amd64-default"]["model"] == "default", "the stranger's default is tested as shipped"
    assert {r["runner"] for r in cells.values()} >= {"ubuntu-22.04", "ubuntu-24.04", "ubuntu-22.04-arm",
                                                     "ubuntu-24.04-arm", "macos-15"}
    assert os.access(ROOT / "scripts" / "install-cell" / "run.sh", os.X_OK)
