# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The dist pull fetches the images the dist `up` will run, and draws like it.

Observed on a controller rolling stack v0.2.91 -> v0.2.93 (`noo upgrade
--all`): the launcher's "Pulling images" phase fetched every first-party
image as `<svc>:v0.2.91@sha256:<old digest>`, then `up` ran v0.2.93. Wasted
bandwidth and the wrong images, end state right only by luck. The same pull
printed compose's PLAIN progress (hundreds of lines) while `up` drew the
in-place display, because the pull's output is piped through `tee`.

What the launcher guarantees now, each pinned here against the REAL script
run in a scratch tree with a fake `docker` (and a fake `sops`/`noo`):

  1. the tag AND the stack.lock digests are re-asserted after the last env
     loader, so a stale pin in the sops store cannot reach the pull;
  2. whatever else diverges, the pull is refused before it downloads when
     compose's own rendering (`config --images`) names a STACK-VERSIONED
     first-party ref of another tag or a digest the lock does not carry -
     and only those: a third-party or monitoring image a mirror put under
     the same prefix (`grafana:12-debian13-dev`, `loki:3`, `nats:latest@…`)
     is pulled as declared (a v0.2.93 -> v0.2.94 roll on host8, 2026-10-07,
     was refused on every one of them, and the stack never rolled);
  3. on a terminal (TERM not dumb) compose writes straight to it and draws
     its own in-place display; a piped compose cannot rewind its frames and
     printed every redraw below the last (the v0.2.95 roll). Off a terminal,
     or on a dumb one, the output is captured and plain. No `--progress`
     flag is forced either way.
"""

from __future__ import annotations

import os
import pty
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "scripts" / "lib-compose.sh"

NEW, OLD = "v0.2.104", "v0.2.103"  # at or above x-noo-secrets-floor
D_NEW = "sha256:" + "3" * 64
D_OLD = "sha256:" + "1" * 64

# Renders what compose would pull/run from the environment it was given -
# which is exactly what the real compose does with the dist image refs.
FAKE_DOCKER = r"""#!/bin/bash
args="$*"
if [ -t 2 ]; then fd2=tty; else fd2=pipe; fi
echo "DOCKER $args | TAG=${NOO_IMAGE_TAG:-} GW=${NOO_IMAGE_DIGEST_GATEWAY:-} FD2=$fd2" >> "$LOGF"
case "$args" in
  "compose version") echo "Docker Compose version v2.30.0" ;;
  *"config --services"*) echo gateway; echo worker ;;
  *"config --images"*)
     echo "${NOO_IMAGE_PREFIX}/gateway:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_GATEWAY:-}"
     echo "${NOO_IMAGE_PREFIX}/worker:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_WORKER:-}"
     echo "postgres:16" ;;
esac
exit 0
"""
# What a controller whose NOO_BASE_REGISTRY mirrors the monitoring images under
# the stack's own prefix renders alongside the stack images (host8, live).
THIRD_PARTY_UNDER_PREFIX = (
    'echo "${NOO_IMAGE_PREFIX}/grafana:12-debian13-dev"\n'
    'echo "${NOO_IMAGE_PREFIX}/loki:3"\n'
    'echo "${NOO_IMAGE_PREFIX}/redis:8.6-debian13-dev"\n'
    'echo "nats:latest@sha256:' + "7" * 64 + '"\n'
)
FAKE_SOPS = """#!/bin/sh
echo "POSTGRES_PASSWORD=a"
echo "NOO_JWT_SECRET=b"
echo "NOO_CLUSTER_SECRET=c"
echo "NOO_BUS_KEY_WORKER=w"
echo "NOO_BUS_KEY_TRELLION=t"
echo "NOO_BUS_KEY_TRELLION_INTEL=i"
echo "NOO_BROWSER_KEY=b"
echo "GRAFANA_PASSWORD=g"
echo "REDIS_PASSWORD=r"
echo "NOO_AUDIT_HMAC_KEY=k"
%s
exit 0
"""


def _tree(tmp: Path, stale_store: bool) -> tuple[Path, dict]:
    work, bindir = tmp / "w", tmp / "bin"
    bindir.mkdir()
    shutil.copytree(ROOT / "scripts", work / "scripts")
    for f in ROOT.glob("docker-compose*.yml"):
        shutil.copy(f, work / f.name)
    for name, body in {
        "docker": FAKE_DOCKER,
        "noo": "#!/bin/sh\nexit 0\n",
        # No listeners on this host, whatever the runner has bound: the
        # launcher's port pre-check asks `ss`, and a busy port on a CI box
        # would stop it before the pull. (The check itself is untouched.)
        "ss": "#!/bin/sh\nexit 1\n",
        "sops": FAKE_SOPS % (
            f"echo NOO_IMAGE_TAG={OLD}\necho NOO_IMAGE_DIGEST_GATEWAY=@{D_OLD}" if stale_store else ""),
    }.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    # A registry login on record, or the launcher goes pull-free.
    (tmp / ".docker").mkdir()
    (tmp / ".docker" / "config.json").write_text('{"auths": {"ghcr.io": {}}}')
    (work / "stack.lock").write_text(f"# tag {NEW}\ngateway@{D_NEW}\n")
    (work / "noomesh.yaml").write_text("compose_env: {}\n")
    (work / "secrets").mkdir()
    (work / "secrets" / "env.sops").write_text("x\n")
    (tmp / "data").mkdir(exist_ok=True)  # the data-root mount guard refuses a data root that is not there
    (work / ".env").write_text(
        f"NOO_IMAGE_TAG={OLD}\nNOO_DATA_ROOT={tmp / 'data'}\nNOO_BIND_MODE=local\nNOO_SECRETS_BACKEND=sops\n")
    # The launcher reads its registry login from ${DOCKER_CONFIG:-$HOME/.docker};
    # a CI runner sets DOCKER_CONFIG itself, without ghcr.io, and the launcher
    # then goes pull-free (no pull phase at all). Inherit nothing of the
    # runner's launcher-facing environment: only PATH and what the harness sets.
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "DOCKER_CONFIG": str(tmp / ".docker"),
        "LOGF": str(tmp / "log"),
        "NOO_CLI_BIN": str(bindir / "noo"),
        "NOO_IMAGE_TAG": NEW,  # what `noo upgrade` puts in the child env
        "HOME": str(tmp),
    }
    return work, env


def _launch(tmp: Path, stale_store: bool = False, tty: bool = False) -> list[str]:
    work, env = _tree(tmp, stale_store)
    kw = dict(cwd=work, env=env, timeout=120, stdin=subprocess.DEVNULL)
    cmd = ["bash", "scripts/noomesh-start.sh", "--dist"]
    if tty:
        master, slave = pty.openpty()
        env["TERM"] = "xterm"
        env.pop("NO_COLOR", None)
        try:
            subprocess.run(cmd, stdout=slave, stderr=slave, **kw)
        finally:
            os.close(slave)
            os.close(master)
    else:
        env.pop("NO_COLOR", None)
        subprocess.run(cmd, capture_output=True, **kw)
    log = tmp / "log"
    return log.read_text().splitlines() if log.exists() else []


def _line(log: list[str], needle: str) -> str:
    hits = [l for l in log if needle in l]
    assert hits, f"no `{needle}` in the docker log:\n" + "\n".join(log)
    return hits[0]


def test_pull_runs_the_tag_and_digest_the_lock_names(tmp_path):
    log = _launch(tmp_path)
    pull = _line(log, " pull ")
    assert f"TAG={NEW}" in pull and f"GW=@{D_NEW}" in pull, pull


def test_a_stale_pin_in_the_secrets_store_cannot_reach_the_pull(tmp_path):
    """The sops store exports unconditionally, after the dist block resolved
    the tag and loaded the lock. The tag was re-asserted already; the digests
    were not."""
    log = _launch(tmp_path, stale_store=True)
    pull = _line(log, " pull ")
    assert f"TAG={NEW}" in pull and f"GW=@{D_NEW}" in pull, pull
    assert D_OLD not in "\n".join(log)


def test_a_pull_of_the_wrong_release_is_refused_before_it_downloads(tmp_path):
    """Defence in depth: whatever makes compose render another tag's refs,
    nothing is pulled."""
    work, env = _tree(tmp_path, stale_store=False)
    # A fake compose that ignores the launcher's pins, as a stale source would.
    d = tmp_path / "bin" / "docker"
    d.write_text(FAKE_DOCKER.replace(
        'echo "${NOO_IMAGE_PREFIX}/gateway:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_GATEWAY:-}"',
        f'echo "${{NOO_IMAGE_PREFIX}}/gateway:{OLD}@{D_OLD}"'))
    r = subprocess.run(["bash", "scripts/noomesh-start.sh", "--dist"], cwd=work, env=env,
                       capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert r.returncode == 1 and "refusing to pull the wrong images" in r.stderr, r.stderr
    assert not any(" pull " in l for l in (tmp_path / "log").read_text().splitlines())


def test_the_pull_owns_the_terminal_when_one_is_attached(tmp_path):
    pull = _line(_launch(tmp_path, tty=True), " pull ")
    assert "FD2=tty" in pull, pull
    assert "--progress" not in pull, pull


def test_the_pull_is_captured_and_plain_off_a_terminal(tmp_path):
    pull = _line(_launch(tmp_path, tty=False), " pull ")
    assert "FD2=pipe" in pull, pull
    assert "--progress" not in pull, pull


def test_a_dumb_terminal_is_captured(tmp_path):
    work, env = _tree(tmp_path, False)
    e = {**env, "TERM": "dumb"}
    master, slave = pty.openpty()
    try:
        subprocess.run(["bash", "scripts/noomesh-start.sh", "--dist"], cwd=work, env=e,
                       stdout=slave, stderr=slave, stdin=subprocess.DEVNULL, timeout=120)
    finally:
        os.close(slave)
        os.close(master)
    pull = _line((tmp_path / "log").read_text().splitlines(), " pull ")
    assert "FD2=pipe" in pull and "--progress" not in pull, pull


def _run(tmp_path, env, work):
    return subprocess.run(["bash", "scripts/noomesh-start.sh", "--dist"], cwd=work, env=env,
                          capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)


def _pull_lines(tmp_path):
    log = tmp_path / "log"
    return [l for l in log.read_text().splitlines() if " pull " in l] if log.exists() else []


def test_third_party_images_under_the_prefix_are_pulled_as_declared(tmp_path):
    """The guard holds only the images the stack versions to the stack tag.
    Monitoring and add-on images a mirror serves under the same prefix carry
    their own tags and must be pulled as compose declares them."""
    work, env = _tree(tmp_path, stale_store=False)
    d = tmp_path / "bin" / "docker"
    d.write_text(FAKE_DOCKER.replace('     echo "postgres:16" ;;',
                                     "     " + THIRD_PARTY_UNDER_PREFIX + '     echo "postgres:16" ;;'))
    r = _run(tmp_path, env, work)
    assert "refusing to pull" not in r.stderr, r.stderr
    pulls = _pull_lines(tmp_path)
    assert pulls and f"TAG={NEW}" in pulls[0], (pulls, r.stderr)


def test_a_stack_versioned_image_at_the_previous_tag_is_still_refused(tmp_path):
    """Unchanged protection, now alongside the third-party refs: a stack
    image rendered at the previous tag while this start runs the new one refuses the pull
    - by tag alone (no digest), and by a lock-pinned name on a foreign tag."""
    for wrong in (f'echo "${{NOO_IMAGE_PREFIX}}/worker:{OLD}"',
                  'echo "${NOO_IMAGE_PREFIX}/gateway:latest"'):
        tmp = tmp_path / wrong.split("/")[1].split(":")[0]
        tmp.mkdir()
        work, env = _tree(tmp, stale_store=False)
        d = tmp / "bin" / "docker"
        d.write_text(FAKE_DOCKER.replace(
            'echo "${NOO_IMAGE_PREFIX}/worker:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_WORKER:-}"',
            THIRD_PARTY_UNDER_PREFIX + "     " + wrong))
        r = _run(tmp, env, work)
        assert r.returncode == 1 and "refusing to pull the wrong images" in r.stderr, (wrong, r.stderr)
        assert not _pull_lines(tmp), wrong


def test_an_operator_profile_in_env_reaches_the_pull_and_the_up(tmp_path):
    # COMPOSE_PROFILES=embed-cpu in .env is how the embed-capacity runbook
    # enables the CPU embedder; compose ignores it beside the launcher's own
    # --profile flags, so the launcher must pass it on (2026-10-09, live).
    work, env = _tree(tmp_path, False)
    with (work / ".env").open("a") as f:
        f.write("COMPOSE_PROFILES=embed-cpu\n")
    env.pop("NO_COLOR", None)
    subprocess.run(["bash", "scripts/noomesh-start.sh", "--dist"], cwd=work, env=env,
                   capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
    log = (tmp_path / "log").read_text().splitlines()
    for verb in (" pull ", " up "):
        line = _line(log, verb)
        assert "--profile embed-cpu" in line, (verb, line)


# The DHI runtime family, as the public channel renders it since 0.6.2:
# NOO_BASE_REGISTRY=<prefix>/dhi nests under the stack's own prefix.
DHI_UNDER_PREFIX = (
    'echo "${NOO_IMAGE_PREFIX}/dhi/grafana:12-debian13-dev"\n'
    'echo "${NOO_IMAGE_PREFIX}/dhi/loki:3"\n'
    'echo "${NOO_IMAGE_PREFIX}/dhi/prometheus:3"\n'
    # A tag with a stack tag's SHAPE: held to the stack tag were it a stack
    # image. Under the base registry it is not, by rule.
    'echo "${NOO_IMAGE_PREFIX}/dhi/redis:v8.6.0"\n'
)


def test_runtime_images_under_the_base_registry_path_are_pulled_as_declared(tmp_path):
    """The `dhi/` base-registry path sits under the image prefix; nothing
    there is a stack image, so none of it is held to the stack tag, while a
    stack image at the wrong tag beside it is still refused."""
    work, env = _tree(tmp_path, stale_store=False)
    env["NOO_IMAGE_PREFIX"] = "ghcr.io/noomesh"
    env["NOO_BASE_REGISTRY"] = "ghcr.io/noomesh/dhi"
    d = tmp_path / "bin" / "docker"
    d.write_text(FAKE_DOCKER.replace('     echo "postgres:16" ;;',
                                     "     " + DHI_UNDER_PREFIX + '     echo "postgres:16" ;;'))
    r = _run(tmp_path, env, work)
    assert "refusing to pull" not in r.stderr, r.stderr
    pulls = _pull_lines(tmp_path)
    assert pulls and f"TAG={NEW}" in pulls[0], (pulls, r.stderr)

    tmp2 = tmp_path / "wrong"
    tmp2.mkdir()
    work, env = _tree(tmp2, stale_store=False)
    env["NOO_IMAGE_PREFIX"] = "ghcr.io/noomesh"
    env["NOO_BASE_REGISTRY"] = "ghcr.io/noomesh/dhi"
    (tmp2 / "bin" / "docker").write_text(FAKE_DOCKER.replace(
        'echo "${NOO_IMAGE_PREFIX}/worker:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_WORKER:-}"',
        DHI_UNDER_PREFIX + f'     echo "${{NOO_IMAGE_PREFIX}}/worker:{OLD}"'))
    r = _run(tmp2, env, work)
    assert r.returncode == 1 and "refusing to pull the wrong images" in r.stderr, r.stderr
