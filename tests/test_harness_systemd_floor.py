# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The applier refuses the harness unit on a systemd too old for its credentials.

The harness unit loads the CA and the harness pair with `LoadCredential=`
(finding 116), which systemd added in 247. An older systemd ignores those
lines, the env still points NOO_TLS_* at /run/credentials/noo-harness.service,
and the harness stops and restarts every 30 s forever. So the applier, when
the bundle's unit uses LoadCredential= and `systemctl --version` says less
than 247:
  * refuses the harness unit (REFUSED line, journal, the `applied:` tag);
  * still applies the harness env, with its three NOO_TLS_* lines back on
    /etc/noo/pki (the files the installed, older unit reads);
  * applies everything else.
`noo cluster verify` reads the tag from the apply report (`harness systemd`).

The real scripts/noo-apply.sh runs in VERIFY-ONLY mode against a signed
bundle (test_apply_full_harness.py's Fleet), with a fake `systemctl` first
on PATH.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# The full-applier harness (a signed bundle, verify-only anchors), loaded by
# path: tests/ is not a package.
_spec = importlib.util.spec_from_file_location("_apply_full_harness", Path(__file__).with_name("test_apply_full_harness.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
Fleet = _mod.Fleet
APPLY = (REPO / "scripts/noo-apply.sh").read_text()
VERIFY = (REPO / "noo-cli/src/commands/cluster_verify.rs").read_text()
UNIT = (REPO / "node-agent-go/deploy/noo-harness.service").read_bytes()
CRED = "/run/credentials/noo-harness.service"
ENV = (
    f"NODE_ID=host3\nNOO_GATEWAY_URL=https://ctl:8000\nNOO_TLS_CA={CRED}/ca.crt\n"
    f"NOO_TLS_CERT={CRED}/node.crt\nNOO_TLS_KEY={CRED}/node.key\n"
).encode()


def _systemctl(fleet: Fleet, version_line: str | None) -> None:
    """A fake systemctl first on PATH: `--version` prints `version_line`."""
    stub = Path(fleet.path.split(":")[0])
    body = "#!/bin/sh\n"
    if version_line is not None:
        body += f'[ "$1" = --version ] && {{ echo "{version_line}"; echo "+PAM +AUDIT"; exit 0; }}\n'
    body += "exit 1\n"
    (stub / "systemctl").write_text(body)
    (stub / "systemctl").chmod(0o755)


def _apply(fleet: Fleet, version_line: str | None) -> subprocess.CompletedProcess:
    _systemctl(fleet, version_line)
    return fleet.apply(fleet.bundle({"harness-unit": UNIT, "harness-env": ENV}))


@pytest.fixture
def fleet(tmp_path: Path) -> Fleet:
    return Fleet(tmp_path)


def test_the_bundle_unit_uses_load_credential() -> None:
    """The precondition of every test below: the unit the gate judges."""
    assert b"\nLoadCredential=" in UNIT


@pytest.mark.parametrize("line", ["systemd 245 (245.4-4ubuntu3.24)", "systemd 246~rc1 (246~rc1-1)"])
def test_below_247_the_harness_unit_is_refused_and_the_rest_applies(fleet: Fleet, line: str) -> None:
    v = re.match(r"systemd (\d+)", line).group(1)
    r = _apply(fleet, line)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert f"REFUSED harness-unit — systemd {v} is older than 247" in r.stderr, r.stderr
    assert f"verify-only: refused: harness-unit=REFUSED-systemd{v}" in r.stdout, r.stdout
    assert "verify-only: every check passed; nothing installed" in r.stdout


@pytest.mark.parametrize("line", ["systemd 247 (247.3-7)", "systemd 255 (255.4-1ubuntu8)"])
def test_at_247_and_above_nothing_is_refused(fleet: Fleet, line: str) -> None:
    r = _apply(fleet, line)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "REFUSED" not in r.stderr and "refused:" not in r.stdout, (r.stdout, r.stderr)


@pytest.mark.parametrize("line", [None, "not systemd", "systemd unknown"])
def test_a_version_that_cannot_be_read_refuses_nothing(fleet: Fleet, line: str | None) -> None:
    """No systemctl (the dind), or one that does not say: today's behaviour."""
    r = _apply(fleet, line)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "REFUSED" not in r.stderr and "refused:" not in r.stdout, (r.stdout, r.stderr)


def _off_credentials() -> str:
    m = re.search(r"^harness_env_off_credentials\(\) \{\n.*?^\}\n", APPLY, re.M | re.S)
    assert m, "noo-apply.sh has no harness_env_off_credentials"
    return m.group(0)


def test_the_env_goes_back_to_the_pki_files_and_nothing_else_changes(tmp_path: Path) -> None:
    env = tmp_path / "harness-env"
    env.write_bytes(ENV + b"NOO_HARNESS_MODEL=m\nNOO_TLS_CA_EXTRA=/run/credentials/noo-harness.service/ca.crt\n")
    subprocess.run(["bash", "-c", _off_credentials() + 'harness_env_off_credentials "$1"', "_", str(env)], check=True)
    assert env.read_text().splitlines() == [
        "NODE_ID=host3",
        "NOO_GATEWAY_URL=https://ctl:8000",
        "NOO_TLS_CA=/etc/noo/pki/ca.crt",
        "NOO_TLS_CERT=/etc/noo/pki/harness/node.crt",
        "NOO_TLS_KEY=/etc/noo/pki/harness/node.key",
        "NOO_HARNESS_MODEL=m",
        "NOO_TLS_CA_EXTRA=/run/credentials/noo-harness.service/ca.crt",
    ]


def test_the_gate_rewrites_the_env_and_drops_only_the_unit() -> None:
    """The refusal branch, as written: the unit is removed from the staged set,
    the env is rewritten (not removed), and the tag joins `applied:`."""
    m = re.search(r'if \[ -n "\$_sdv" \] && \[ "\$_sdv" -lt "\$HARNESS_SYSTEMD_FLOOR" \]; then\n(.*?)\n    fi\n', APPLY, re.S)
    assert m, "the floor branch moved"
    body = m.group(1)
    assert 'rm -f "$WORK/files/harness-unit"' in body
    assert "harness-env" not in body.replace('harness_env_off_credentials "$WORK/files/harness-env"', "").replace(
        '[ -f "$WORK/files/harness-env" ] && ', ""), body
    assert 'applied="$HARNESS_REFUSED"' in APPLY, "the tag must open the applied: line"


def test_the_applier_and_verify_agree_on_the_tag_and_the_floor() -> None:
    tag = re.search(r'^HARNESS_SYSTEMD_REFUSED_TAG="([^"]+)"$', APPLY, re.M).group(1)
    floor = re.search(r"^HARNESS_SYSTEMD_FLOOR=(\d+)$", APPLY, re.M).group(1)
    assert f'pub(crate) const HARNESS_SYSTEMD_REFUSED_TAG: &str = "{tag}";' in VERIFY
    assert f"pub(crate) const HARNESS_SYSTEMD_FLOOR: u32 = {floor};" in VERIFY
    assert floor == "247", "LoadCredential= arrived in systemd 247"
    assert "checks.extend(harness_systemd_check(&apply_reports));" in VERIFY
