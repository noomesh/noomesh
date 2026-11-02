# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo stack restart --force` runs the signed digests, as start does.

0.6.5-rc.1 rehearsal (2026-10-16): after enabling voice, `noo stack restart
--force` recreated every core container by TAG - `ollama/ollama:0.40.5`,
`gateway:v0.6.5-rc.1`, no `@sha256` - because only noomesh-start.sh read
stack.lock. Both now call the one reader, lib-dist.sh dist_load_stack_lock;
a recreate under distribution mode with no lock for its tag is refused.

Runs the REAL scripts/noomesh-restart.sh --force in a scratch dist install
with a fake `docker` (and `noo`, `sops`) on PATH. The fake records the
environment compose is handed at `up`; the test then renders every
digest-carrying `image:` line of the REAL compose files with that
environment, the interpolation compose itself would do.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAG = "v0.6.5-rc.1"

FAKE_DOCKER = r"""#!/bin/bash
args="$*"
echo "DOCKER $args" >> "$LOGF"
case "$args" in
  "compose version") echo "Docker Compose version v2.30.0" ;;
  *"config --services"*) echo gateway; echo worker; echo ollama ;;
  *"config --format json"*) echo '{"services":{}}' ;;
  *" up "*) env | grep -E '^NOO_IMAGE_(TAG|PREFIX|DIGEST_[A-Z0-9_]+)=' > "$ENVDUMP" ;;
esac
exit 0
"""
FAKE_SOPS = """#!/bin/sh
for k in POSTGRES_PASSWORD NOO_JWT_SECRET NOO_CLUSTER_SECRET NOO_BUS_KEY_WORKER \\
         NOO_BUS_KEY_TRELLION NOO_BUS_KEY_TRELLION_INTEL NOO_BROWSER_KEY GRAFANA_PASSWORD REDIS_PASSWORD; do
  echo "$k=x$k"
done
# A stale pin in the secrets store must not survive into the recreate.
echo "NOO_IMAGE_DIGEST_GATEWAY=@sha256:%s"
exit 0
""" % ("1" * 64)

IMAGE_LINE = re.compile(r"^\s*image:\s*(.*NOO_IMAGE_DIGEST_[A-Z0-9_]+.*?)\s*$")


def _locked_names() -> list[str]:
    """Every image the compose files pin by digest, as its lock row names it."""
    names: set[str] = set()
    for f in ROOT.glob("docker-compose*.yml"):
        for m in re.finditer(r"NOO_IMAGE_DIGEST_([A-Z0-9_]+)", f.read_text()):
            names.add(m.group(1).lower().replace("_", "-"))
    assert len(names) >= 8, names  # the parse found the stack images
    return sorted(names)


def _interpolate(s: str, env: dict[str, str]) -> str:
    """${V}, ${V:-default}, ${V:?msg}, nested defaults - innermost first."""
    pat = re.compile(r"\$\{([A-Z0-9_]+)(?:(:-|:\?)([^${}]*))?\}")
    while True:
        m = pat.search(s)
        if not m:
            return s
        var, op, arg = m.group(1), m.group(2), m.group(3) or ""
        val = env.get(var, "")
        if not val and op == ":-":
            val = arg
        assert val or op != ":?", f"{var} unset: {arg}"
        s = s[: m.start()] + val + s[m.end():]


def _install(tmp: Path, lock: str | None) -> tuple[Path, dict[str, str]]:
    work, bindir = tmp / "w", tmp / "bin"
    bindir.mkdir()
    shutil.copytree(ROOT / "scripts", work / "scripts")
    for f in ROOT.glob("docker-compose*.yml"):
        shutil.copy(f, work / f.name)
    for name, body in {"docker": FAKE_DOCKER, "sops": FAKE_SOPS,
                       "noo": "#!/bin/sh\ncat >/dev/null 2>&1 || true\nexit 0\n",
                       "ss": "#!/bin/sh\nexit 1\n"}.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    if lock is not None:
        (work / "stack.lock").write_text(lock)
    (work / "noomesh.yaml").write_text("compose_env: {}\n")
    (work / "secrets").mkdir()
    (work / "secrets" / "env.sops").write_text("x\n")
    (tmp / "data").mkdir(exist_ok=True)  # the data-root mount guard refuses a data root that is not there
    (work / ".env").write_text(
        f"NOO_INSTALL_MODE=dist\nNOO_IMAGE_TAG={TAG}\nNOO_DATA_ROOT={tmp / 'data'}\n"
        "NOO_BIND_MODE=local\nNOO_SECRETS_BACKEND=sops\n")
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp),
        "LOGF": str(tmp / "log"),
        "ENVDUMP": str(tmp / "env-at-up"),
        "NOO_CLI_BIN": str(bindir / "noo"),
    }
    return work, env


def _restart(tmp: Path, lock: str | None, *names: str) -> subprocess.CompletedProcess:
    work, env = _install(tmp, lock)
    return subprocess.run(["bash", "scripts/noomesh-restart.sh", "--force", *names], cwd=work, env=env,
                          capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)


def _lock(tag: str = TAG) -> str:
    # two hex digits per row, offset so no row can read as the stale store pin (64 x '1')
    rows = "".join(f"{n}@sha256:{format(i + 0x20, '02x') * 32}\n" for i, n in enumerate(_locked_names(), start=2))
    return f"# tag {tag}\n{rows}source:trellion@{'a' * 40}\n"


def _rendered(tmp: Path) -> dict[str, str]:
    dump = tmp / "env-at-up"
    assert dump.exists(), "the restart never reached `up`"
    env = dict(l.split("=", 1) for l in dump.read_text().splitlines() if "=" in l)
    refs: dict[str, str] = {}
    for f in (tmp / "w").glob("docker-compose*.yml"):
        for line in f.read_text().splitlines():
            m = IMAGE_LINE.match(line)
            if m:
                var = re.search(r"NOO_IMAGE_DIGEST_([A-Z0-9_]+)", m.group(1)).group(1)
                refs[var.lower().replace("_", "-")] = _interpolate(m.group(1).strip("\"'"), env)
    return refs


def test_force_restart_with_the_lock_renders_every_locked_image_by_digest(tmp_path: Path) -> None:
    r = _restart(tmp_path, _lock())
    assert r.returncode == 0, r.stderr
    refs = _rendered(tmp_path)
    lock = dict(l.split("@", 1) for l in _lock().splitlines() if l and not l.startswith(("#", "source:")))
    assert set(lock) <= set(refs), (set(lock) - set(refs))
    for name, digest in lock.items():
        assert refs[name].endswith(f"@{digest}"), (name, refs[name])
    # the core images the rehearsal saw by tag
    assert "/ollama:" in refs["ollama"] and "@sha256:" in refs["ollama"], refs["ollama"]  # our hardened image (i323)
    assert f"/gateway:{TAG}@sha256:" in refs["gateway"], refs["gateway"]
    # the stale store pin did not survive
    assert "1" * 64 not in "\n".join(refs.values())


def test_named_force_restart_loads_the_lock_too(tmp_path: Path) -> None:
    r = _restart(tmp_path, _lock(), "gateway")
    assert r.returncode == 0, r.stderr
    assert "@sha256:" in _rendered(tmp_path)["gateway"]


def test_force_restart_without_a_lock_in_dist_mode_is_refused(tmp_path: Path) -> None:
    r = _restart(tmp_path, None)
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert f"no stack.lock for {TAG} — refusing to recreate by tag" in r.stderr, r.stderr
    assert f"noo upgrade --stack --tag {TAG}" in r.stderr, r.stderr
    assert not (tmp_path / "env-at-up").exists()


def test_force_restart_with_another_tags_lock_is_refused(tmp_path: Path) -> None:
    r = _restart(tmp_path, _lock("v0.6.4"))
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert f"stack.lock is not for {TAG}" in r.stderr, r.stderr
    assert not (tmp_path / "env-at-up").exists()
