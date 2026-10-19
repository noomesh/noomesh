# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher hands redis/grafana data to uid 65532 recursively, verified.

0.6.3 -> 0.6.4 (2026-10-16): redis moved to uid 65532 and the launcher's
re-own ran minutes before `up`, while the old root container was still
rewriting its files. ``appendonlydir/appendonly.aof.manifest`` came back
root-owned and the new redis crash-looped for three hours. The re-own now
runs right before `up`, stops the service first, chowns recursively and
re-probes; anything still not 65532 refuses the start.

Tests cannot chown to 65532, so the alpine runner is replaced through
``NOO_REOWN_CMD`` with a fake whose ``find``/``chown`` act on a ledger of
"root-owned" paths: the probe prints the ledger, chown -R empties it (or,
for the stuck case, does not).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-reown.sh"
START = ROOT / "scripts" / "noomesh-start.sh"

# The fake runner: `<runner> <host dir> <snippet>`. $D is the host dir; the
# fake `find` prints the ledger for that dir, the fake `chown` records its
# args and clears the ledger unless REOWN_STUCK is set.
FAKE_RUNNER = r"""#!/bin/bash
dir="$1"; snippet="$2"
ledger="$dir/.ledger"
bin="$(mktemp -d)"
cat > "$bin/find" <<FIND
#!/bin/bash
echo "find \$*" >> "$LOG"
[ -f "$ledger" ] && cat "$ledger"
exit 0
FIND
cat > "$bin/chown" <<CHOWN
#!/bin/bash
echo "chown \$*" >> "$LOG"
[ -n "\${REOWN_STUCK:-}" ] || : > "$ledger"
CHOWN
chmod +x "$bin/find" "$bin/chown"
D="$dir" PATH="$bin:$PATH" sh -c "$snippet"
"""


def _setup(tmp: Path) -> tuple[Path, Path, Path]:
    root = tmp / "data"
    runner = tmp / "runner.sh"
    runner.write_text(FAKE_RUNNER)
    runner.chmod(0o755)
    log = tmp / "log"
    log.write_text("")
    return root, runner, log


def _run(tmp: Path, runner: Path, log: Path, args: str, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, NOO_REOWN_CMD=str(runner), LOG=str(log))
    env.update(extra or {})
    script = (
        f'set -e; source "{LIB}"; '
        f'reown_stop_service() {{ echo "stop $1" >> "{log}"; }}; '
        f"reown_nonroot_dirs {args}"
    )
    return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=False, cwd=tmp)


def _seed(root: Path, svc: str, paths: list[str]) -> Path:
    d = root / svc
    (d / "appendonlydir").mkdir(parents=True, exist_ok=True)
    (d / ".ledger").write_text("".join(f"{d}/{p}\n" for p in paths))
    return d


def test_nested_root_owned_file_is_reowned_recursively_and_verified(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    d = _seed(root, "redis", ["appendonlydir/appendonly.aof.manifest", "dump.rdb"])
    r = _run(tmp_path, runner, log, f'"{root}" redis')
    assert r.returncode == 0, r.stderr
    assert f"re-owned 2 path(s) under {d} to 65532" in r.stdout, r.stdout
    calls = log.read_text().splitlines()
    chowns = [c for c in calls if c.startswith("chown")]
    assert chowns == [f"chown -R 65532:65532 {d}"], calls
    # stop BEFORE chown, and a verify probe AFTER it
    assert calls.index("stop redis") < calls.index(chowns[0]), calls
    finds = [i for i, c in enumerate(calls) if c.startswith("find")]
    assert len(finds) == 2 and finds[-1] > calls.index(chowns[0]), calls
    assert all("-user 65532" in calls[i] and "-group 65532" in calls[i] for i in finds), calls


def test_already_65532_is_a_silent_noop(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    _seed(root, "redis", [])
    _seed(root, "grafana", [])
    r = _run(tmp_path, runner, log, f'"{root}" redis grafana')
    assert r.returncode == 0 and r.stdout == "" and r.stderr == "", r
    calls = log.read_text().splitlines()
    assert not any(c.startswith(("chown", "stop")) for c in calls), calls
    assert sum(c.startswith("find") for c in calls) == 2, calls


def test_paths_left_after_chown_refuse_the_start_naming_them(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    d = _seed(root, "redis", ["appendonlydir/appendonly.aof.manifest"])
    r = _run(tmp_path, runner, log, f'"{root}" redis', {"REOWN_STUCK": "1"})
    assert r.returncode == 1, r
    assert f"{d}/appendonlydir/appendonly.aof.manifest" in r.stderr, r.stderr
    assert f"sudo chown -R 65532:65532 {d}" in r.stderr, r.stderr
    assert "re-owned" not in r.stdout


def test_grafana_too_and_a_missing_dir_is_skipped(tmp_path: Path) -> None:
    root, runner, log = _setup(tmp_path)
    d = _seed(root, "grafana", ["grafana.db"])
    r = _run(tmp_path, runner, log, f'"{root}" redis grafana')
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == f"re-owned 1 path(s) under {d} to 65532", r.stdout
    assert "stop grafana" in log.read_text()


# ── the REAL launcher, run end to end with fakes ──────────────────────
# 0.6.5-rc.1 rehearsal (2026-10-16): the re-own above never ran. The launcher
# `unset _data_root` ~400 lines before the call sites, both guarded by
# `if [ -n "$_data_root" ]`, so the seeded root-owned AOF manifest reached the
# new uid-65532 redis and it crash-looped exactly as on 0.6.4. The textual
# test that stood here (call count + ordering in the source) passed anyway.
# This one executes scripts/noomesh-start.sh --dist in a scratch tree with a
# fake `docker`, `noo`, `sops` and `ss` on PATH and NOO_REOWN_CMD faked, and
# reads ONE ordered log all of them append to: it fails if the re-own is
# unreachable (verified by re-adding the unset).

LAUNCH_DOCKER = r"""#!/bin/bash
args="$*"
echo "DOCKER $args" >> "$LOGF"
case "$args" in
  "compose version") echo "Docker Compose version v2.30.0" ;;
  *"config --services"*) echo gateway; echo redis; echo worker ;;
  *"config --images"*)
     echo "${NOO_IMAGE_PREFIX}/gateway:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_GATEWAY:-}"
     echo "${NOO_IMAGE_PREFIX}/worker:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_WORKER:-}" ;;
  *"config --format json"*) echo '{"services":{}}' ;;
esac
exit 0
"""
LAUNCH_NOO = """#!/bin/bash
echo "NOO $*" >> "$LOGF"
cat >/dev/null 2>&1 <&0 || true
exit 0
"""
# `<runner> <host dir> <snippet>`: the first probe reports one root-owned
# file, the chown clears it, the verify probe then finds nothing.
LAUNCH_REOWN = r"""#!/bin/bash
echo "REOWN $1 :: $2" >> "$LOGF"
case "$2" in
  find*) [ -f "$1/.ledger" ] && cat "$1/.ledger" ;;
  chown*) : > "$1/.ledger" ;;
esac
exit 0
"""
LAUNCH_SOPS = """#!/bin/sh
for k in POSTGRES_PASSWORD NOO_JWT_SECRET NOO_CLUSTER_SECRET NOO_BUS_KEY_WORKER \
         NOO_BUS_KEY_TRELLION NOO_BUS_KEY_TRELLION_INTEL NOO_BROWSER_KEY GRAFANA_PASSWORD REDIS_PASSWORD NOO_AUDIT_HMAC_KEY; do
  echo "$k=x$k"
done
exit 0
"""
TAG = "v0.2.104"  # at or above x-noo-secrets-floor


def _launch_tree(tmp: Path) -> tuple[Path, dict[str, str], Path]:
    import shutil

    work, bindir, data = tmp / "w", tmp / "bin", tmp / "data"
    bindir.mkdir()
    shutil.copytree(ROOT / "scripts", work / "scripts")
    for f in ROOT.glob("docker-compose*.yml"):
        shutil.copy(f, work / f.name)
    for name, body in {"docker": LAUNCH_DOCKER, "noo": LAUNCH_NOO, "sops": LAUNCH_SOPS,
                       "ss": "#!/bin/sh\nexit 1\n", "reown": LAUNCH_REOWN}.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    (work / "stack.lock").write_text(f"# tag {TAG}\ngateway@sha256:{'3' * 64}\n")
    (work / "noomesh.yaml").write_text("compose_env: {}\n")
    (work / "secrets").mkdir()
    (work / "secrets" / "env.sops").write_text("x\n")
    (work / ".env").write_text(
        f"NOO_IMAGE_TAG={TAG}\nNOO_DATA_ROOT={data}\nNOO_BIND_MODE=local\nNOO_SECRETS_BACKEND=sops\n")
    redis = data / "redis"
    (redis / "appendonlydir").mkdir(parents=True)
    (redis / ".ledger").write_text("/d/appendonlydir/appendonly.aof.manifest\n")
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp),
        "DOCKER_CONFIG": str(tmp / ".docker"),  # no login: pull-free
        "LOGF": str(tmp / "log"),
        "NOO_CLI_BIN": str(bindir / "noo"),
        "NOO_IMAGE_TAG": TAG,
        "NOO_REOWN_CMD": str(bindir / "reown"),
    }
    return work, env, redis


@pytest.mark.parametrize("named", [[], ["redis"]], ids=["full-profile", "named-service"])
def test_the_real_launcher_reowns_redis_before_the_bind_check_and_the_up(tmp_path: Path, named: list[str]) -> None:
    """Both start paths: the whole profile and `noo stack start redis`."""
    work, env, redis = _launch_tree(tmp_path)
    r = subprocess.run(["bash", "scripts/noomesh-start.sh", "--dist", *named], cwd=work, env=env,
                       capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
    log = (tmp_path / "log").read_text().splitlines() if (tmp_path / "log").exists() else []
    dump = f"rc={r.returncode}\nSTDOUT:\n{r.stdout[-3000:]}\nSTDERR:\n{r.stderr[-3000:]}\nLOG:\n" + "\n".join(log)

    def first(pred) -> int:
        hits = [i for i, l in enumerate(log) if pred(l)]
        assert hits, dump
        return hits[0]

    up = first(lambda l: l.startswith("DOCKER compose") and " up -d " in l)
    chown = first(lambda l: l.startswith(f"REOWN {redis} :: chown -R 65532:65532"))
    stop = first(lambda l: l.startswith("DOCKER compose") and l.endswith(" stop redis"))
    bind = first(lambda l: l.startswith("NOO config launch-check bind-sources"))
    # the re-own was INVOKED on the redis dir, with the old redis stopped
    # first, verified after, and all of it before the bind-source check and
    # the `up` (the check stays the last thing before `up`).
    assert stop < chown < bind < up, dump
    probes = [i for i, l in enumerate(log) if l.startswith(f"REOWN {redis} :: find")]
    assert len(probes) == 2 and probes[0] < chown < probes[1] < bind, dump
    assert f"re-owned 1 path(s) under {redis} to 65532" in r.stdout, dump
    assert r.returncode == 0, dump


def test_the_lib_is_embedded_in_the_cli() -> None:
    assert '"scripts/lib-reown.sh"' in (ROOT / "noo-cli" / "build.rs").read_text()
