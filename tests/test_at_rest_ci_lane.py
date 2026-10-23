# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The i10a at-rest TPM lane cannot rot into a green check that proves nothing.

.github/workflows/at-rest-tpm.yml runs tests/ci/at-rest-tpm.sh against a
software TPM on a GitHub-hosted runner. These pin its SHAPE (the lane itself
only runs in CI): it exists, it is hosted ubuntu-24.04, nothing on the TPM path
is allowed to fail softly, and the script FAILS (it does not skip) when no TPM
device appears, which is also exercised here for real.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows/at-rest-tpm.yml"
SCRIPT = ROOT / "tests/ci/at-rest-tpm.sh"


def _doc() -> dict:
    return yaml.safe_load(WF.read_text())


def _steps() -> list[dict]:
    return _doc()["jobs"]["at-rest-tpm"]["steps"]


def test_the_lane_and_its_script_exist():
    assert WF.is_file() and SCRIPT.is_file()
    assert "set -euo pipefail" in SCRIPT.read_text()


def test_it_runs_on_hosted_ubuntu_2404_and_triggers_on_pr_merge_group_dispatch():
    doc = _doc()
    assert doc["jobs"]["at-rest-tpm"]["runs-on"] == "ubuntu-24.04"
    on = doc.get("on") or doc.get(True)
    assert {"pull_request", "merge_group", "workflow_dispatch"} <= set(on), on
    paths = " ".join(on["pull_request"]["paths"])
    for needle in ("atrest", "cmd/noo-hostd", "scripts/lib-secrets.sh", "at-rest-tpm"):
        assert needle in paths, needle


def test_the_lane_never_fails_softly():
    text = WF.read_text()
    assert not re.search(r"continue-on-error\s*:", text), "no step of this lane may continue on error"
    for step in _steps():
        if step.get("name") != "Collect diagnostics":  # best-effort by design, runs only on failure
            assert "|| true" not in step.get("run", ""), step.get("name")
    assert "pull_request_target" not in text


def test_the_lane_runs_the_three_tpm_stages_in_order_and_uploads_logs_on_failure():
    names = [s.get("name", "") for s in _steps()]
    joined = "\n".join(s.get("run", "") for s in _steps())
    assert joined.index("setup-tpm") < joined.index("assert-device") < joined.index("at-rest-tpm.sh test")
    up = [s for s in _steps() if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    assert up and up[0].get("if") == "failure()", names


def test_no_tpm_path_command_is_allowed_to_fail_softly_in_the_script():
    critical = re.compile(
        r"seal-age-key|systemd-creds (encrypt|decrypt|has-tpm2)|cryptenroll|systemd-cryptsetup|"
        r"tpm2_pcrextend|tpm2_pcrread|create-volume|swtpm chardev|luksDump"
    )
    bad = [
        f"{i}: {ln.strip()}"
        for i, ln in enumerate(SCRIPT.read_text().splitlines(), 1)
        if critical.search(ln) and "|| true" in ln and not ln.lstrip().startswith("#")
    ]
    assert not bad, "\n".join(bad)


def test_the_script_fails_when_no_tpm_device_appears():
    src = SCRIPT.read_text()
    assert re.search(r"die\(\)\s*\{[^}]*exit 1", src)
    assert "no TPM device appeared" in src
    assert not re.search(r"\bexit 0\b", src), "an `exit 0` in this script is a way to skip"


def test_assert_device_really_exits_nonzero_without_a_tpm(tmp_path):
    r = subprocess.run(
        ["bash", str(SCRIPT), "assert-device"],
        env={"PATH": "/usr/bin:/bin", "TPMRM_GLOB": str(tmp_path / "tpmrm*"), "TPM_WAIT_SECS": "1"},
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode != 0, r.stdout + r.stderr
    assert "no TPM device appeared" in r.stderr


def test_assert_device_passes_when_a_device_node_exists(tmp_path):
    (tmp_path / "tpmrm7").write_text("")
    r = subprocess.run(
        ["bash", str(SCRIPT), "assert-device"],
        env={"PATH": "/usr/bin:/bin", "TPMRM_GLOB": str(tmp_path / "tpmrm*"), "TPM_WAIT_SECS": "1"},
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr


def test_every_conditional_skip_is_explicit_and_only_for_a_verb_missing_from_the_tree():
    """The only skips: no `at-rest` verb at all (before PR-B), or create-volume
    absent / without --size-mib (before PR-C). Each logs SKIPPED (explicit) and
    raises a workflow warning; the TPM device and has-tpm2 checks are never
    conditional."""
    src = SCRIPT.read_text()
    assert src.count("SKIPPED (explicit)") == 3
    assert src.count("::warning title=at-rest-tpm::") == 3
    assert src.index("SKIPPED (explicit)") > src.index("systemd-creds has-tpm2")
