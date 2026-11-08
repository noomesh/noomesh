# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo stack restart <name>` for a service with no container creates it, and
"Services restarted" means every named service is running.

An rc.1 rehearsal scan (2026-11-08, noomesh-internal i580): `noo stack
restart <addon>` printed "Services restarted" and exited 0 for an add-on with
no container. The plain branch ran `docker compose restart <svc>`, which does
nothing for a missing container, and nothing checked the result. That is the
remedy the after-boot alert tells the operator to run.

Runs the REAL scripts/noomesh-restart.sh (no --force) in a scratch dev
install. A fake `docker` on PATH keeps one container's state in a file: absent
until `up` creates it, running unless FAKE_DEAD is set.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAKE_DOCKER = r"""#!/bin/bash
args="$*"
echo "DOCKER $args" >> "$LOGF"
case "$args" in
  "compose version") echo "Docker Compose version v2.30.0" ;;
  *"config --services"*) echo gateway; echo worker ;;
  *"config --format json"*) echo '{"services":{}}' ;;
  *" up "*) touch "$STATE/created" ;;
  *" ps -q --status running "*)
    [ -f "$STATE/created" ] && [ -z "${FAKE_DEAD:-}" ] && echo cid-gateway ;;
  *" ps -aq "*) [ -f "$STATE/created" ] && echo cid-gateway ;;
  "inspect --format {{.State.Status}}"*)
    if [ -n "${FAKE_DEAD:-}" ]; then echo exited; else echo running; fi ;;
esac
exit 0
"""
FAKE_SOPS = """#!/bin/sh
for k in POSTGRES_PASSWORD NOO_JWT_SECRET NOO_CLUSTER_SECRET NOO_BUS_KEY_WORKER \\
         NOO_BUS_KEY_TRELLION NOO_BUS_KEY_TRELLION_INTEL NOO_BROWSER_KEY GRAFANA_PASSWORD REDIS_PASSWORD; do
  echo "$k=x$k"
done
exit 0
"""


def _restart(tmp: Path, *, exists: bool, dead: bool = False) -> tuple[subprocess.CompletedProcess, str]:
    work, bindir, state = tmp / "w", tmp / "bin", tmp / "state"
    bindir.mkdir()
    state.mkdir()
    if exists:
        (state / "created").touch()
    shutil.copytree(ROOT / "scripts", work / "scripts")
    for f in ROOT.glob("docker-compose*.yml"):
        shutil.copy(f, work / f.name)
    for name, body in {"docker": FAKE_DOCKER, "sops": FAKE_SOPS,
                       "noo": "#!/bin/sh\ncat >/dev/null 2>&1 || true\nexit 0\n",
                       "ss": "#!/bin/sh\nexit 1\n"}.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    (work / "noomesh.yaml").write_text("compose_env: {}\n")
    (work / "secrets").mkdir()
    (work / "secrets" / "env.sops").write_text("x\n")
    (tmp / "data").mkdir()
    (work / ".env").write_text(f"NOO_DATA_ROOT={tmp / 'data'}\nNOO_BIND_MODE=local\nNOO_SECRETS_BACKEND=sops\n")
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp),
        "LOGF": str(tmp / "log"),
        "STATE": str(state),
        "NOO_CLI_BIN": str(bindir / "noo"),
    }
    if dead:
        env["FAKE_DEAD"] = "1"
    r = subprocess.run(["bash", "scripts/noomesh-restart.sh", "gateway"], cwd=work, env=env,
                       capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)
    log = (tmp / "log").read_text() if (tmp / "log").exists() else ""
    return r, log


def _compose_calls(log: str, verb: str) -> list[str]:
    return [l for l in log.splitlines() if l.startswith("DOCKER compose ") and f" {verb} " in f"{l} "]


def test_a_named_service_with_no_container_is_created_not_restarted(tmp_path: Path) -> None:
    r, log = _restart(tmp_path, exists=False)
    assert r.returncode == 0, (r.stdout, r.stderr)
    ups = _compose_calls(log, "up")
    assert ups, f"no `up` for a service with no container; compose calls:\n{log}"
    assert "--no-deps" in ups[0] and ups[0].rstrip().endswith("gateway"), ups[0]
    assert not _compose_calls(log, "restart"), "a missing container was `restart`ed, which does nothing"


def test_a_named_service_not_running_afterwards_fails_and_names_it(tmp_path: Path) -> None:
    r, _ = _restart(tmp_path, exists=True, dead=True)
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert "not running after the restart: gateway" in out, out
    assert "Services restarted" not in out, out
