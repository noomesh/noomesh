# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An add-on whose signed pin does not verify for the running stack is left
out of the launch, loudly; the core stack and every other add-on start.

The 0.6.11 rehearsal (B-zz-addonpin.sh) found that ONE third-party add-on
signed `--supports v0.6.10` only, on an install moved to 0.6.11, made
`noo stack restart --force` refuse the WHOLE stack (gateway, auth, Postgres)
before compose. The operator approved the change on 2026-10-24: that add-on is
excluded from the compose set instead, with a `REFUSED add-on <name>: <why>`
line and its remedy, and the closing line says it did NOT start.

Runs the REAL scripts/noomesh-restart.sh --force in a scratch dist install
with fake `docker`, `noo` and `sops` on PATH (no daemon, no registry). The
fake `noo` answers `addons launch-pins` with the protocol the real one prints;
the Rust side of that verb is unit-tested in noo-cli/src/commands/addon_pins.rs.
A stack.lock for another tag still refuses the whole restart.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAG = "v0.6.11"
PREV = "v0.6.10"
OTHER_REF = "ghcr.io/example/other-addon@sha256:" + "2" * 64
RHOLD_REF = "localhost/rh/rhold@sha256:" + "3" * 64

# The refused add-on, shaped like the rehearsal's `rhold`, and a good one.
RHOLD_OVERLAY = """services:
  noo-rhold:
    image: ${NOO_ADDON_IMAGE_RHOLD:-noo-addon-unpinned.invalid/rhold:x}
    container_name: noo-rhold
    env_file: ./rhold.env
    labels:
      noo.addon: rhold
    network_mode: none
    restart: "no"
"""
OTHER_OVERLAY = """services:
  other-addon:
    image: ${NOO_ADDON_IMAGE_OTHER_ADDON:-noo-addon-unpinned.invalid/other-addon:x}
"""

PINS = (
    f"refuse rhold rhold is pinned for stack {PREV}, and this stack runs {TAG}\n"
    f"verified other_addon 2.1.0 {TAG}\n"
    f"pin other_addon NOO_ADDON_IMAGE_OTHER_ADDON {OTHER_REF}\n"
    "decl other_addon system.json\n"
)

FAKE_DOCKER = r"""#!/bin/bash
args="$*"
echo "DOCKER $args" >> "$LOGF"
case "$args" in
  "compose version") echo "Docker Compose version v2.30.0" ;;
  "image inspect"*) for r in $FAKE_LOCAL; do [ "$r" = "$3" ] && exit 0; done; exit 1 ;;
  "ps -q"*"com.docker.compose.service=noo-rhold"*) echo cid-rhold ;;
  *"config --services"*) echo gateway; echo worker; echo ollama ;;
  *"config --format json"*)
    printf '{"services":{"gateway":{"image":"g"},"other-addon":{"image":"%s"},"noo-rhold":{"image":"%s"}}}' \
      "${NOO_ADDON_IMAGE_OTHER_ADDON:-unset}" "${NOO_ADDON_IMAGE_RHOLD:-unset}" ;;
  *" up "*)
    echo "$args" > "$UPARGS"
    env | grep -E '^NOO_(ADDON_IMAGE_[A-Z0-9_]+|ADDONS_[A-Z]+)=' | sort > "$ENVDUMP" ;;
esac
exit 0
"""
FAKE_NOO = """#!/bin/sh
case "$1 $2 $3" in
  "config launch-render addons") printf 'rhold=1\\nother_addon=1\\n'; exit 0 ;;
esac
case "$1 $2" in
  "addons launch-pins") echo "$*" >> "$NOOLOG"; printf '%s' "$FAKE_PINS"; exit 0 ;;
esac
cat >/dev/null 2>&1 || true
exit 0
"""
FAKE_SOPS = """#!/bin/sh
for k in POSTGRES_PASSWORD NOO_JWT_SECRET NOO_CLUSTER_SECRET NOO_BUS_KEY_WORKER \\
         NOO_BUS_KEY_TRELLION NOO_BUS_KEY_TRELLION_INTEL NOO_BROWSER_KEY GRAFANA_PASSWORD REDIS_PASSWORD; do
  echo "$k=x$k"
done
exit 0
"""


def _locked_names() -> list[str]:
    names: set[str] = set()
    for f in ROOT.glob("docker-compose*.yml"):
        for m in re.finditer(r"NOO_IMAGE_DIGEST_([A-Z0-9_]+)", f.read_text()):
            names.add(m.group(1).lower().replace("_", "-"))
    assert len(names) >= 8, names  # the parse found the stack images
    return sorted(names)


def _lock(signed_tag: str = TAG) -> str:
    rows = "".join(f"{n}@sha256:{format(i + 0x20, '02x') * 32}\n" for i, n in enumerate(_locked_names(), start=2))
    return f"# stack {signed_tag}\n# tag {TAG}\n{rows}"


def _restart(tmp: Path, lock: str, pins: str = PINS) -> subprocess.CompletedProcess:
    work, bindir = tmp / "w", tmp / "bin"
    bindir.mkdir()
    shutil.copytree(ROOT / "scripts", work / "scripts")
    for f in ROOT.glob("docker-compose*.yml"):
        shutil.copy(f, work / f.name)
    for name, body in {"docker": FAKE_DOCKER, "sops": FAKE_SOPS, "noo": FAKE_NOO, "ss": "#!/bin/sh\nexit 1\n"}.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    (work / "stack.lock").write_text(lock)
    (work / "noomesh.yaml").write_text("compose_env: {}\naddons:\n  rhold: true\n  other_addon: true\n")
    for name, text in (("rhold", RHOLD_OVERLAY), ("other_addon", OTHER_OVERLAY)):
        (work / "addons" / name).mkdir(parents=True)
        (work / "addons" / name / "docker-compose.yml").write_text(text)
        (work / "addons" / name / "system.json").write_text('{"schema": "%s"}\n' % name)
    # What an earlier start (rhold still verified then) handed the gateway.
    (work / ".noo-addon-systems" / "rhold").mkdir(parents=True)
    (work / ".noo-addon-systems" / "rhold" / "system.json").write_text('{"schema": "rhold"}\n')
    (work / "secrets").mkdir()
    (work / "secrets" / "env.sops").write_text("x\n")
    (tmp / "data").mkdir(exist_ok=True)
    (work / ".env").write_text(
        f"NOO_INSTALL_MODE=dist\nNOO_IMAGE_TAG={TAG}\nNOO_DATA_ROOT={tmp / 'data'}\n"
        "NOO_BIND_MODE=local\nNOO_SECRETS_BACKEND=sops\n")
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp),
        "LOGF": str(tmp / "log"),
        "ENVDUMP": str(tmp / "env-at-up"),
        "UPARGS": str(tmp / "up-args"),
        "NOOLOG": str(tmp / "noo-log"),
        "NOO_CLI_BIN": str(bindir / "noo"),
        "FAKE_PINS": pins,
        "FAKE_LOCAL": f"{OTHER_REF} {RHOLD_REF}",
        # Inherited values must never vouch for, or hide, an add-on.
        "NOO_ADDONS_VERIFIED": f"rhold=0.1.0@{TAG}",
        "NOO_ADDON_IMAGE_RHOLD": RHOLD_REF,
    }
    return subprocess.run(["bash", "scripts/noomesh-restart.sh", "--force"], cwd=work, env=env,
                          capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)


def _env_at_up(tmp: Path) -> dict[str, str]:
    dump = tmp / "env-at-up"
    assert dump.exists(), "the restart never reached `up`"
    return dict(l.split("=", 1) for l in dump.read_text().splitlines() if "=" in l)


def test_a_stale_addon_pin_leaves_that_addon_out_and_the_stack_restarts(tmp_path: Path) -> None:
    r = _restart(tmp_path, _lock())
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    # Loud: the refusal, its reason and remedy, and an outcome that names it.
    assert f"REFUSED add-on rhold: rhold is pinned for stack {PREV}, and this stack runs {TAG}" in r.stderr, out
    assert "Fix:  noo addons upgrade rhold   (or turn it off: noo addons disable rhold)" in r.stderr, out
    assert "Services restarted WITHOUT add-on(s) rhold: refused, NOT running" in out, out
    assert "Services restarted\n" not in re.sub(r"\x1b\[[0-9;]*m", "", out)
    # The launcher asked about both add-ons, from its install root.
    asked = (tmp_path / "noo-log").read_text().split()
    assert {"rhold", "other_addon"} <= set(asked), asked
    # Compose: the core plus the other add-on; the refused overlay is nowhere.
    up = (tmp_path / "up-args").read_text()
    assert "docker-compose.cluster.yml" in up and "addons/other_addon/docker-compose.yml" in up, up
    log = (tmp_path / "log").read_text()
    assert "addons/rhold/docker-compose.yml" not in log, "a refused overlay is never composed, in any form"
    env = _env_at_up(tmp_path)
    assert env.get("NOO_ADDON_IMAGE_OTHER_ADDON") == OTHER_REF, env
    assert "NOO_ADDON_IMAGE_RHOLD" not in env, "an inherited image variable never names a refused add-on"
    # The gateway's verdict names only what runs; the broker is told what was refused.
    assert env.get("NOO_ADDONS_VERIFIED") == f"other_addon=2.1.0@{TAG}", env
    assert env.get("NOO_ADDONS_REFUSED") == "rhold", env
    # Its bundle declaration from an earlier start is withdrawn; the other's is handed over.
    work = tmp_path / "w"
    assert not (work / ".noo-addon-systems" / "rhold").exists(), "a refused add-on's system.json is not handed to the gateway"
    assert (work / ".noo-addon-systems" / "other_addon" / "system.json").is_file()
    # A container left from an earlier start is stopped, by compose's labels.
    assert "DOCKER stop cid-rhold" in log, log


def test_with_no_refusal_the_outcome_is_a_plain_restart(tmp_path: Path) -> None:
    pins = PINS.replace(f"refuse rhold rhold is pinned for stack {PREV}, and this stack runs {TAG}\n",
                        f"verified rhold 0.1.0 {TAG}\npin rhold NOO_ADDON_IMAGE_RHOLD {RHOLD_REF}\n")
    r = _restart(tmp_path, _lock(), pins)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "REFUSED" not in out and "WITHOUT add-on" not in out, out
    assert "addons/rhold/docker-compose.yml" in (tmp_path / "up-args").read_text()
    env = _env_at_up(tmp_path)
    assert env.get("NOO_ADDON_IMAGE_RHOLD") == RHOLD_REF
    assert "NOO_ADDONS_REFUSED" not in env, env


def test_a_tampered_stack_lock_still_refuses_the_whole_restart(tmp_path: Path) -> None:
    # The signed tag line inside stack.lock says another release: a
    # stack-level problem, so nothing is recreated, add-on refusal or not.
    r = _restart(tmp_path, _lock(signed_tag=PREV))
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert f"stack.lock is not for {TAG}" in r.stderr, r.stderr
    assert not (tmp_path / "up-args").exists(), "a refused stack must never reach `up`"


def test_the_start_launcher_stops_refused_addons_and_says_what_did_not_start() -> None:
    start = (ROOT / "scripts/noomesh-start.sh").read_text()
    up = start.index("noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d --force-recreate")
    assert up < start.index("    addons_stop_refused\n"), "start stops a refused add-on's leftover container after `up`"
    assert 'ui_close_warned "Services started WITHOUT add-on(s)' in start
    assert "    addons_report_refused\n" in start
