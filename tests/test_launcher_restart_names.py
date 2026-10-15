# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo stack restart <name>`: names resolve, compose failure is not success.

Live 2026-10-14 (pop-os): `noo stack restart evolve` -> compose "no such
service: evolve" -> "Services restarted", exit 0. scripts/lib-restart.sh now
resolves the names `noo stack status` shows (evolve -> noo-evolve), add-on keys
(x-noo-addon `containers:`), refuses unknown names listing the valid ones, and
reports pin drift. Driven through a fake `docker` on PATH.
"""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"

FAKE_DOCKER = r"""#!/bin/bash
# fake docker: services gateway noo-evolve trellion-intel
args="$*"
case "$args" in
  *"config --services"*) printf 'gateway\nnoo-evolve\ntrellion-intel\n' ;;
  *"config --format json"*) echo '{"services":{"noo-evolve":{"image":"evolve:new"}}}' ;;
  *"image inspect"*) echo sha256:new ;;
  *" ps -q noo-evolve"*) echo cid1 ;;
  "inspect "*) echo "${FAKE_RUNNING_IMAGE:-sha256:new}" ;;
  *" restart "*)
    for a in "$@"; do
      case "$a" in nonesuch|evolve) echo "no such service: $a" >&2; exit 1 ;; esac
    done
    echo "restarted $*" ;;
esac
exit 0
"""


def run(tmp_path: Path, body: str, running: str = "sha256:new") -> subprocess.CompletedProcess:
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir(exist_ok=True)
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)
    (tmp_path / "evolve.yml").write_text(
        "x-noo-addon:\n  addon: evolve\n  containers: [noo-evolve]\nservices: {}\n"
    )
    (tmp_path / "intel.yml").write_text(
        "x-noo-addon:\n  addon: trellion_intel\n  containers: [noo-trellion-intel]\nservices: {}\n"
    )
    script = textwrap.dedent(
        f"""
        export PATH="{fake.parent}:$PATH" FAKE_RUNNING_IMAGE="{running}"
        . {SCRIPTS}/lib-ui.sh
        . {SCRIPTS}/lib-compose.sh
        . {SCRIPTS}/lib-restart.sh
        CF="-f {tmp_path}/evolve.yml -f {tmp_path}/intel.yml"
        VALID="$(restart_valid_services $CF)"
        {body}
        """
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)


def test_status_table_name_maps_to_compose_service(tmp_path):
    r = run(tmp_path, 'restart_resolve_all "$VALID" $CF -- evolve gateway; echo "${RESOLVED_SERVICES[*]}"')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == "noo-evolve gateway"


def test_addon_key_maps_through_containers_list(tmp_path):
    r = run(tmp_path, 'restart_resolve_all "$VALID" $CF -- trellion_intel; echo "${RESOLVED_SERVICES[*]}"')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == "trellion-intel"


def test_unknown_name_refuses_and_lists_valid_services(tmp_path):
    r = run(tmp_path, 'restart_resolve_all "$VALID" $CF -- nonesuch')
    assert r.returncode == 1
    assert "unknown service: nonesuch" in r.stderr
    assert "gateway noo-evolve trellion-intel" in r.stderr


def test_launcher_checks_compose_exit_status():
    src = (SCRIPTS / "noomesh-restart.sh").read_text()
    assert "restart_resolve_all" in src and "RESTART_RC" in src
    # the success line is only reachable past the failure exits
    assert src.index("exit \"$RESTART_RC\"") < src.index('ui_close_done "Services restarted"')


def test_drift_reports_service_on_old_image(tmp_path):
    r = run(tmp_path, 'restart_image_drift $CF -- noo-evolve', running="sha256:old")
    assert r.stdout.strip() == "noo-evolve"


def test_no_drift_when_running_image_is_current(tmp_path):
    r = run(tmp_path, 'restart_image_drift $CF -- noo-evolve')
    assert r.stdout.strip() == ""
