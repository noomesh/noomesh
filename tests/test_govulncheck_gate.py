# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""scripts/govulncheck-gate.py: reachable vulnerabilities fail the go-vulncheck
lane unless a scoped, dated exception covers the same id, module and version."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "govulncheck-gate.py"
REAL_EXC = ROOT / "node-agent-go" / "govulncheck-exceptions.json"
REAL_OUT = ROOT / "tests" / "fixtures" / "govulncheck-real.json"

EXC = {
    "id": "GO-2026-6278",
    "module": "github.com/gorilla/websocket",
    "found_version": "v1.5.3",
    "expires": "2026-12-15",
    "reason": "test",
}


def finding(osv="GO-2026-6278", module="github.com/gorilla/websocket",
            version="v1.5.3", symbol=True):
    top = {"module": module, "version": version, "package": module + "/x"}
    if symbol:
        top["function"] = "WriteMessage"
    trace = [top]
    if symbol:
        trace.append({"module": "example.com/agent", "package": "example.com/agent/p",
                      "function": "caller"})
    return {"finding": {"osv": osv, "fixed_version": "v9.9.9", "trace": trace}}


def run(tmp_path, findings, excs=(EXC,), today="2026-11-23", raw_exc=None, stream=None):
    out = tmp_path / "out.json"
    if stream is None:
        stream = [{"config": {"scanner_name": "govulncheck"}}] + list(findings)
    out.write_text("\n".join(json.dumps(o, indent=2) for o in stream))
    exc = tmp_path / "exc.json"
    exc.write_text(raw_exc if raw_exc is not None else json.dumps(list(excs)))
    return subprocess.run([sys.executable, str(GATE), str(out), str(exc), "--today", today],
                          capture_output=True, text=True)


def test_excepted_finding_passes(tmp_path):
    r = run(tmp_path, [finding(), finding()])
    assert r.returncode == 0, r.stdout
    assert "GO-2026-6278" in r.stdout and "2026-12-15" in r.stdout
    assert "2 reachable trace" in r.stdout


def test_other_id_same_module_fails(tmp_path):
    r = run(tmp_path, [finding(), finding(osv="GO-2020-0019")])
    assert r.returncode == 1
    assert "GO-2020-0019" in r.stdout


def test_same_id_other_module_fails(tmp_path):
    r = run(tmp_path, [finding(), finding(module="github.com/other/ws")])
    assert r.returncode == 1
    assert "github.com/other/ws" in r.stdout


def test_same_id_module_other_version_fails(tmp_path):
    r = run(tmp_path, [finding(version="v1.5.4")])
    assert r.returncode == 1
    assert "v1.5.4" in r.stdout


def test_expired_exception_fails(tmp_path):
    r = run(tmp_path, [finding()], today="2026-12-16")
    assert r.returncode == 1
    assert "expired" in r.stdout and "bump was due" in r.stdout


def test_exception_valid_on_expiry_day(tmp_path):
    assert run(tmp_path, [finding()], today="2026-12-15").returncode == 0


def test_stale_exception_fails(tmp_path):
    r = run(tmp_path, [])
    assert r.returncode == 1
    assert "stale" in r.stdout


def test_package_level_finding_ignored(tmp_path):
    r = run(tmp_path, [finding(), finding(osv="GO-2020-0019", symbol=False)])
    assert r.returncode == 0, r.stdout


def test_package_level_finding_does_not_keep_exception_alive(tmp_path):
    r = run(tmp_path, [finding(symbol=False)])
    assert r.returncode == 1 and "stale" in r.stdout


def test_no_exceptions_clean_run_passes(tmp_path):
    assert run(tmp_path, [finding(symbol=False)], excs=()).returncode == 0


def test_malformed_files_fail(tmp_path):
    bad_date = dict(EXC, expires="15/12/2026")
    missing = {k: v for k, v in EXC.items() if k != "reason"}
    for raw in (json.dumps([bad_date]), json.dumps([missing]),
                json.dumps([EXC, EXC]), "not json", json.dumps({"id": "x"})):
        r = run(tmp_path, [finding()], raw_exc=raw)
        assert r.returncode == 1, raw


def test_output_without_config_fails(tmp_path):
    assert run(tmp_path, [], stream=[]).returncode == 1


def test_real_govulncheck_output_passes_with_real_exceptions(tmp_path):
    """REAL_OUT is `govulncheck -format json ./...` (v1.1.4) run in
    node-agent-go on dev, so this proves the gate reads the real format."""
    r = subprocess.run([sys.executable, str(GATE), str(REAL_OUT), str(REAL_EXC),
                        "--today", "2026-11-23"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
    assert "GO-2026-6278" in r.stdout
